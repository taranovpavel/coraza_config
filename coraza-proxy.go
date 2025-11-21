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

	// Create WAF with minimal configuration
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

# ===== XSS PROTECTION RULES =====

# Базовые XSS паттерны
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx (?i)<script[^>]*>" \
    "phase:1,deny,status:403,id:1001,msg:'XSS: Script tag detected'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx (?i)</script>" \
    "phase:1,deny,status:403,id:1002,msg:'XSS: Closing script tag'"

# JavaScript protocol
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx (?i)javascript:" \
    "phase:1,deny,status:403,id:1003,msg:'XSS: JavaScript protocol'"

# Event handlers
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx (?i)\bon\w+\s*=" \
    "phase:1,deny,status:403,id:1004,msg:'XSS: Event handler detected'"

# Dangerous functions
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx (?i)(alert|confirm|prompt)\s*\\(" \
    "phase:1,deny,status:403,id:1005,msg:'XSS: Dangerous function call'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx (?i)eval\\s*\\(" \
    "phase:1,deny,status:403,id:1006,msg:'XSS: eval function detected'"

# Document object manipulation
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx (?i)document\\.(cookie|location|write|domain)" \
    "phase:1,deny,status:403,id:1007,msg:'XSS: Document object access'"

# HTML entities and encoding bypass
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx (?i)&lt;script|%3cscript|&#x3c;script" \
    "phase:1,deny,status:403,id:1008,msg:'XSS: Encoded script tag'"

# Iframe and object tags
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx (?i)<iframe[^>]*>|<object[^>]*>|<embed[^>]*>" \
    "phase:1,deny,status:403,id:1009,msg:'XSS: Embedded object tag'"

# SVG with scripts
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx (?i)<svg[^>]*>.*<script" \
    "phase:1,deny,status:403,id:1010,msg:'XSS: SVG with script'"

# Data URI scheme
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx (?i)data:text/html" \
    "phase:1,deny,status:403,id:1011,msg:'XSS: Data URI scheme'"

# CSS expressions (IE)
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx (?i)expression\\s*\\(" \
    "phase:1,deny,status:403,id:1012,msg:'XSS: CSS expression'"

# VBScript
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx (?i)vbscript:" \
    "phase:1,deny,status:403,id:1013,msg:'XSS: VBScript protocol'"

# Meta tag refresh
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx (?i)<meta[^>]*http-equiv\\s*=\\s*[\"']?refresh" \
    "phase:1,deny,status:403,id:1014,msg:'XSS: Meta refresh'"

# Form action hijacking
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx (?i)<form[^>]*action\\s*=\\s*[\"']?javascript:" \
    "phase:1,deny,status:403,id:1015,msg:'XSS: Form action hijacking'"

# Link hijacking
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx (?i)<a[^>]*href\\s*=\\s*[\"']?javascript:" \
    "phase:1,deny,status:403,id:1016,msg:'XSS: Link hijacking'"

# Image with onerror
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx (?i)<img[^>]*onerror\\s*=" \
    "phase:1,deny,status:403,id:1017,msg:'XSS: Image with onerror'"

# Input tags with events
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx (?i)<input[^>]*on\\w+\\s*=" \
    "phase:1,deny,status:403,id:1018,msg:'XSS: Input with event handler'"

# Style tags with expressions
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx (?i)<style[^>]*>.*@import" \
    "phase:1,deny,status:403,id:1019,msg:'XSS: Style with import'"

# Base tag hijacking
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx (?i)<base[^>]*href\\s*=\\s*[\"']?javascript:" \
    "phase:1,deny,status:403,id:1020,msg:'XSS: Base tag hijacking'"

SecRule ARGS|ARGS_NAMES "@rx javascript:" "phase:1,deny,status:403,id:12002,msg:'XSS javascript detected'"

SecRule ARGS|ARGS_NAMES "@rx on\\w+\\s*=" "phase:1,deny,status:403,id:12003,msg:'XSS event handler detected'"

# SQL Injection Protection
SecRule ARGS|ARGS_NAMES "@rx union.*select" "phase:1,deny,status:403,id:11001,msg:'SQL Injection detected'"

SecRule ARGS|ARGS_NAMES "@rx or.*1=1" "phase:1,deny,status:403,id:11002,msg:'SQL Injection detected'"

# Path Traversal Protection
SecRule REQUEST_FILENAME|ARGS|ARGS_NAMES "@rx \\.\\./" "phase:1,deny,status:403,id:13001,msg:'Path traversal detected'"

# Command Injection Protection
SecRule ARGS|ARGS_NAMES "@rx \\|.*rm" "phase:1,deny,status:403,id:14001,msg:'Command injection detected'"

# Static files - no inspection
SecRule REQUEST_FILENAME "@rx \\.(css|js|png|jpg|jpeg|gif|ico)$" "phase:1,pass,id:30001,ctl:ruleEngine=Off"

# Или через регулярное выражение FTP
SecRule REQUEST_FILENAME "@rx ^/ftp(/|$)" "phase:1,deny,status:403,id:10003,msg:'FTP path blocked'"
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

	// Simple request processing - only check URL and headers
	// Process URI
	tx.ProcessURI(r.URL.String(), r.Method, r.Proto)
	
	// Process headers
	for key, values := range r.Header {
		for _, value := range values {
			tx.AddRequestHeader(key, value)
		}
	}
	tx.ProcessRequestHeaders()

	// Process request body if needed for specific endpoints
	if r.Body != nil && (strings.Contains(r.URL.Path, "/api/") || strings.Contains(r.URL.Path, "/rest/")) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			p.logger.Error("Failed to read body", zap.Error(err))
			http.Error(w, "Internal Error", http.StatusInternalServerError)
			return
		}
		r.Body = io.NopCloser(bytes.NewBuffer(body))
		
		// Process request body parameters manually
		if len(body) > 0 {
			// Simple body inspection for common attack patterns
			if p.detectAttackInBody(body) {
				p.logger.Warn("Attack detected in request body", 
					zap.String("ip", clientIP),
					zap.String("path", r.URL.Path))
				http.Error(w, "Request blocked by security rules", http.StatusForbidden)
				return
			}
		}
	}

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

func (p *CorazaProxy) detectAttackInBody(body []byte) bool {
	patterns := []string{
		`<script[^>]*>`,
		`javascript:`,
		`on\\w+\\s*=`,
		`union.*select`,
		`or.*1=1`,
		`\\.\\./`,
	}
	
	bodyStr := string(body)
	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, bodyStr); matched {
			return true
		}
	}
	return false
}

func (p *CorazaProxy) modifyResponse(res *http.Response) error {
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
		`on\\w+\\s*=\\s*"[^"]*"`,
	}
	for _, pattern := range patterns {
		if matched, _ := regexp.Match(pattern, body); matched {
			return true
		}
	}
	return false
}

func main() {
	backendURL := "192.168.0.185:3000"
	if len(os.Args) > 1 {
		backendURL = os.Args[1]
	}

	proxy, err := NewCorazaProxy(backendURL)
	if err != nil {
		log.Fatal("Failed to create proxy:", err)
	}

	port := "8090"
	if len(os.Args) > 2 {
		port = os.Args[2]
	}

	log.Printf("Starting Coraza proxy on port %s, forwarding to %s", port, backendURL)
	log.Fatal(http.ListenAndServe(":"+port, proxy))
}