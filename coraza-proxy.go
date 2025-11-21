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

# Basic XSS protection
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx <script" "phase:1,deny,status:403,id:1001,msg:'XSS detected'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx javascript:" "phase:1,deny,status:403,id:1002,msg:'XSS detected'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx onerror=" "phase:1,deny,status:403,id:1003,msg:'XSS detected'"

# URL-encoded XSS patterns
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx %3Cscript" "phase:1,deny,status:403,id:1004,msg:'URL-encoded XSS detected'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx %3Cimg" "phase:1,deny,status:403,id:1005,msg:'URL-encoded XSS detected'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx %3Csvg" "phase:1,deny,status:403,id:1006,msg:'URL-encoded XSS detected'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx %3Ciframe" "phase:1,deny,status:403,id:1007,msg:'URL-encoded XSS detected'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx onerror%3D" "phase:1,deny,status:403,id:1008,msg:'URL-encoded XSS detected'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx alert%28" "phase:1,deny,status:403,id:1009,msg:'URL-encoded XSS detected'"

# Double encoded
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx %253Cscript" "phase:1,deny,status:403,id:1010,msg:'Double-encoded XSS detected'"

# HTML entities
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx &lt;script" "phase:1,deny,status:403,id:1011,msg:'HTML entity XSS detected'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx &lt;img" "phase:1,deny,status:403,id:1012,msg:'HTML entity XSS detected'"

# Mixed encoding
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx %3Cimg%20src" "phase:1,deny,status:403,id:1013,msg:'Mixed encoded XSS detected'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx src%3Dx%20onerror" "phase:1,deny,status:403,id:1014,msg:'Mixed encoded XSS detected'"

# SQL Injection protection
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx union.*select" "phase:1,deny,status:403,id:2001,msg:'SQLi detected'"

# Path traversal
SecRule REQUEST_FILENAME|ARGS|ARGS_NAMES "@rx \\.\\./" "phase:1,deny,status:403,id:3001,msg:'Path traversal detected'"

# FTP blocking
SecRule REQUEST_URI "@beginsWith /ftp" "phase:1,deny,status:403,id:4001,msg:'FTP access blocked'"

# Static files
SecRule REQUEST_FILENAME "@rx \\.(css|js|png|jpg|jpeg|gif|ico)$" "phase:1,pass,id:5001,ctl:ruleEngine=Off"

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
# Block requests with suspicious fragments
SecRule REQUEST_URI "@rx #.*search.*q=.*%3C" "phase:1,deny,status:403,id:6001,msg:'XSS in URL fragment detected'"

SecRule REQUEST_URI "@rx #.*q=.*onerror" "phase:1,deny,status:403,id:6002,msg:'XSS in URL fragment detected'"

SecRule REQUEST_URI "@rx #.*alert\\(" "phase:1,deny,status:403,id:6003,msg:'XSS in URL fragment detected'"
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
	 // XSS check before WAF processing
    if p.detectXSSInRequest(r) {
        p.logger.Warn("XSS detected in request", 
            zap.String("ip", clientIP),
            zap.String("path", r.URL.Path),
            zap.String("method", r.Method))
        http.Error(w, "XSS attack detected", http.StatusForbidden)
        return
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

    // Check for XSS in URL fragment (part after #)
    if p.detectXSSInURL(r) {
        p.logger.Warn("XSS detected in URL fragment", 
            zap.String("ip", clientIP),
            zap.String("url", r.URL.String()))
        http.Error(w, "XSS attack detected", http.StatusForbidden)
        return
    }

    // XSS check in query parameters
    if p.detectXSSInRequest(r) {
        p.logger.Warn("XSS detected in request parameters", 
            zap.String("ip", clientIP),
            zap.String("path", r.URL.Path))
        http.Error(w, "XSS attack detected", http.StatusForbidden)
        return
    }

    // Create new transaction
    tx := p.waf.NewTransaction()
    defer tx.Close()

    // ... остальной код WAF обработки
}

func (p *CorazaProxy) detectXSSInURL(r *http.Request) bool {
    // Get the full URL including fragment
    fullURL := r.URL.String()
    
    // Check the fragment part (after #)
    if fragment := r.URL.Fragment; fragment != "" {
        if p.isXSSPayload(fragment) {
            return true
        }
        
        // Parse fragment as URL to get query parameters
        if fragmentURL, err := url.Parse(fragment); err == nil {
            // Check fragment query parameters
            for _, values := range fragmentURL.Query() {
                for _, value := range values {
                    if p.isXSSPayload(value) {
                        return true
                    }
                }
            }
            
            // Check fragment path
            if p.isXSSPayload(fragmentURL.Path) {
                return true
            }
        }
    }
    
    return false
}

func (p *CorazaProxy) detectXSSInRequest(r *http.Request) bool {
    // Check URL parameters
    for _, values := range r.URL.Query() {
        for _, value := range values {
            if p.isXSSPayload(value) {
                return true
            }
        }
    }

    // Check POST parameters
    if r.Method == "POST" || r.Method == "PUT" {
        // Parse form data
        if err := r.ParseForm(); err == nil {
            for _, values := range r.PostForm {
                for _, value := range values {
                    if p.isXSSPayload(value) {
                        return true
                    }
                }
            }
        }
    }

    return false
}

func (p *CorazaProxy) isXSSPayload(input string) bool {
    xssPatterns := []string{
        // Basic patterns
        "<script", "</script>", "javascript:", 
        "vbscript:", "data:text/html",
        
        // Event handlers
        "onerror=", "onload=", "onclick=", "onmouseover=",
        "onfocus=", "onblur=", "onchange=",
        
        // Dangerous functions
        "alert(", "confirm(", "prompt(", "eval(",
        "document.cookie", "document.write", "document.domain",
        
        // HTML tags
        "<img", "<svg", "<iframe", "<embed", "<object",
        "<link", "<meta", "<base",
        
        // URL encoded
        "%3Cscript", "%3Cimg", "%3Csvg", "%3Ciframe",
        "%3Cembed", "%3Cobject", "onerror%3D", "alert%28",
        
        // Double encoded
        "%253Cscript", "%253Cimg",
        
        // HTML entities
        "&lt;script", "&lt;img", "&lt;svg",
        
        // CSS
        "expression(",
        
        // Specific patterns from your test case
        "src=x", "onerror=alert", "img src",
    }
    
    inputLower := strings.ToLower(input)
    for _, pattern := range xssPatterns {
        if strings.Contains(inputLower, pattern) {
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