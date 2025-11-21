package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/corazawaf/coraza/v3"
	"go.uber.org/zap"
)

type CorazaProxy struct {
	waf           coraza.WAF
	logger        *zap.Logger
	backendURL    string
	reverseProxy  *httputil.ReverseProxy
	bruteForceMap map[string]*BruteForceCounter
}

type BruteForceCounter struct {
	Count     int
	LastSeen  time.Time
	Blocked   bool
	BlockUntil time.Time
}

func NewCorazaProxy(backendURL string) (*CorazaProxy, error) {
	logger, err := zap.NewProduction()
	if err != nil {
		return nil, err
	}

	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithDirectives(loadCustomRules()),
	)
	if err != nil {
		return nil, err
	}

	proxy := &CorazaProxy{
		waf:           waf,
		logger:        logger,
		backendURL:    backendURL,
		bruteForceMap: make(map[string]*BruteForceCounter),
	}

	proxy.reverseProxy = &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = "http"
			req.URL.Host = strings.TrimPrefix(backendURL, "http://")
			req.Host = strings.TrimPrefix(backendURL, "http://")
		},
		ModifyResponse: proxy.modifyResponse,
		ErrorHandler:   proxy.errorHandler,
	}

	go proxy.cleanupBruteForceCounters()

	return proxy, nil
}

func loadCustomRules() string {
	rules := `
SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimit 134217728
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain text/html text/xml
SecResponseBodyLimit 524288

SecAuditEngine RelevantOnly
SecAuditLogParts "ABIJDEFHZ"

# XSS Protection
SecRule ARGS|ARGS_NAMES|REQUEST_BODY|REQUEST_HEADERS "@rx (?i)(<script[^>]*>|</script>|javascript:|\balert\s*\()" "phase:1,deny,status:403,id:12001,msg:'XSS attack detected'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY|REQUEST_HEADERS "@rx (?i)(\bon\w+\s*=)" "phase:1,deny,status:403,id:12002,msg:'XSS event handlers detected'"

# SQL Injection Protection
SecRule ARGS|ARGS_NAMES|REQUEST_BODY|REQUEST_HEADERS "@rx (?i)(union\s+select|or\s+1=1|drop\s+table)" "phase:1,deny,status:403,id:11001,msg:'SQL Injection detected'"

# Path Traversal Protection
SecRule REQUEST_FILENAME|ARGS|ARGS_NAMES "@rx (\.\./|\.\.\\|/etc/passwd)" "phase:1,deny,status:403,id:13001,msg:'Path traversal detected'"

# Command Injection Protection
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx (\|\s*rm\s+-rf|\|\s*wget\s+)" "phase:1,deny,status:403,id:14001,msg:'Command injection detected'"

# Static files - no inspection
SecRule REQUEST_FILENAME "@rx \.(css|js|png|jpg|jpeg|gif|ico)$" "phase:1,pass,id:30001,ctl:ruleEngine=Off"
`

	return rules
}

func (p *CorazaProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	clientIP := p.getClientIP(r)

	// Brute force protection
	if p.isBruteForceBlocked(clientIP) {
		p.logger.Warn("Brute force blocked", zap.String("ip", clientIP))
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	// Count login attempts
	if strings.Contains(r.URL.Path, "/rest/user/login") {
		p.incrementBruteForceCounter(clientIP)
	}

	// Create new transaction
	tx := p.waf.NewTransaction()
	defer tx.Close()

	// Process request manually
	// Set request headers
	for key, values := range r.Header {
		for _, value := range values {
			tx.AddRequestHeader(key, value)
		}
	}

	// Process request body
	if r.Body != nil {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			p.logger.Error("Failed to read body", zap.Error(err))
			http.Error(w, "Internal Error", http.StatusInternalServerError)
			return
		}
		r.Body = io.NopCloser(bytes.NewBuffer(body))
		
		// Write body to transaction
		if _, err := tx.RequestBodyWriter().Write(body); err != nil {
			p.logger.Error("Failed to write body to WAF", zap.Error(err))
		}
	}

	// Process URI and method
	tx.ProcessURI(r.URL.String(), r.Method, r.Proto)
	tx.ProcessRequestHeaders()

	// Check if request was interrupted (blocked)
	if it := tx.Interruption(); it != nil {
		p.logger.Warn("Request blocked by WAF",
			zap.String("ip", clientIP),
			zap.String("path", r.URL.Path),
			zap.Int("status", it.Status),
			zap.Int("rule_id", it.RuleID))
		http.Error(w, fmt.Sprintf("Request blocked by security rule %d", it.RuleID), it.Status)
		return
	}

	// If request passed WAF, proxy to backend
	p.reverseProxy.ServeHTTP(w, r)
}

func (p *CorazaProxy) modifyResponse(res *http.Response) error {
	// Simple response modification
	contentType := res.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/html") || strings.Contains(contentType, "application/json") {
		body, err := io.ReadAll(res.Body)
		if err != nil {
			return err
		}
		res.Body.Close()

		// Simple XSS detection in response
		if p.detectResponseXSS(body) {
			p.logger.Warn("Potential XSS in response detected")
		}

		// Put the body back
		res.Body = io.NopCloser(bytes.NewBuffer(body))
		res.ContentLength = int64(len(body))
		res.Header.Set("Content-Length", strconv.Itoa(len(body)))
	}
	return nil
}

func (p *CorazaProxy) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	p.logger.Error("Proxy error", zap.Error(err))
	http.Error(w, "Bad Gateway", http.StatusBadGateway)
}

func (p *CorazaProxy) getClientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		return strings.TrimSpace(strings.Split(forwarded, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (p *CorazaProxy) isBruteForceBlocked(ip string) bool {
	p.cleanupBruteForceCounters()
	if counter, exists := p.bruteForceMap[ip]; exists {
		if counter.Blocked && time.Now().Before(counter.BlockUntil) {
			return true
		}
		if counter.Count > 10 {
			counter.Blocked = true
			counter.BlockUntil = time.Now().Add(time.Hour)
			return true
		}
	}
	return false
}

func (p *CorazaProxy) incrementBruteForceCounter(ip string) {
	now := time.Now()
	if counter, exists := p.bruteForceMap[ip]; exists {
		if now.Sub(counter.LastSeen) > 5*time.Minute {
			counter.Count = 1
		} else {
			counter.Count++
		}
		counter.LastSeen = now
	} else {
		p.bruteForceMap[ip] = &BruteForceCounter{
			Count:    1,
			LastSeen: now,
		}
	}
}

func (p *CorazaProxy) cleanupBruteForceCounters() {
	now := time.Now()
	for ip, counter := range p.bruteForceMap {
		if !counter.Blocked && now.Sub(counter.LastSeen) > 10*time.Minute {
			delete(p.bruteForceMap, ip)
		}
		if counter.Blocked && now.After(counter.BlockUntil) {
			delete(p.bruteForceMap, ip)
		}
	}
}

func (p *CorazaProxy) detectResponseXSS(body []byte) bool {
	patterns := []string{
		`<script[^>]*>.*?</script>`,
		`on\w+\s*=\s*"[^"]*"`,
	}
	for _, pattern := range patterns {
		if matched, _ := regexp.Match(pattern, body); matched {
			return true
		}
	}
	return false
}

func main() {
	backendURL := "http://localhost:3000"
	if len(os.Args) > 1 {
		backendURL = os.Args[1]
	}

	proxy, err := NewCorazaProxy(backendURL)
	if err != nil {
		log.Fatal("Failed to create proxy:", err)
	}

	port := "8080"
	if len(os.Args) > 2 {
		port = os.Args[2]
	}

	log.Printf("Starting Coraza proxy on port %s, forwarding to %s", port, backendURL)
	log.Fatal(http.ListenAndServe(":"+port, proxy))
}