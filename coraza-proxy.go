package main

import (
	"bufio"
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
	"github.com/corazawaf/coraza/v3/experimental/plugins/macro"
	"github.com/corazawaf/coraza/v3/types"
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
	Count    int
	LastSeen time.Time
	Blocked  bool
	BlockUntil time.Time
}

func NewCorazaProxy(backendURL string) (*CorazaProxy, error) {
	logger, err := zap.NewProduction()
	if err != nil {
		return nil, err
	}

	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithErrorCallback(logError).
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

	// Initialize reverse proxy
	proxy.reverseProxy = &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = "http"
			req.URL.Host = strings.TrimPrefix(backendURL, "http://")
			req.Host = strings.TrimPrefix(backendURL, "http://")
		},
		ModifyResponse: proxy.modifyResponse,
		ErrorHandler:   proxy.errorHandler,
	}

	// Start cleanup goroutine for brute force protection
	go proxy.cleanupBruteForceCounters()

	return proxy, nil
}

func loadCustomRules() string {
	// Базовые настройки Coraza
	rules := `
# Basic configuration
SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimit 134217728
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain text/html text/xml
SecResponseBodyLimit 524288

# Audit engine configuration  
SecAuditEngine RelevantOnly
SecAuditLogParts "ABIJDEFHZ"

# ===== DISABLE ANNOYING DEFAULT RULES =====
SecRuleUpdateTargetById 920280 "!REQUEST_HEADERS:Host"
SecRuleUpdateTargetById 920350 "!REQUEST_HEADERS:Host" 
SecRuleUpdateTargetById 920270 "!REQUEST_HEADERS:User-Agent"
SecRuleUpdateTargetById 933151 "!ARGS:email"
SecRuleUpdateTargetById 932150 "!ARGS:email"

# ===== ENHANCED XSS PROTECTION - FIXED =====
# Rule 1: Basic XSS patterns
SecRule ARGS|ARGS_NAMES|REQUEST_BODY|REQUEST_HEADERS "@rx (?i)(<script[^>]*>|</script>|javascript:\s*|vbscript:\s*|\balert\s*\(\s*|eval\s*\(\s*|document\.(cookie|location|write))" \
    "phase:1,deny,status:403,id:12001,msg:'XSS attack detected - basic patterns',tag:'attack-xss'"

# Rule 2: Event handlers - FIXED for <img onerror=>
SecRule ARGS|ARGS_NAMES|REQUEST_BODY|REQUEST_HEADERS "@rx (?i)(\bon\w+\s*=|\bonafterprint\s*=|\bonbeforeprint\s*=|\bonbeforeunload\s*=|\bonerror\s*=|\bonhashchange\s*=|\bonload\s*=|\bonmessage\s*=|\bonoffline\s*=|\bononline\s*=|\bonpagehide\s*=|\bonpageshow\s*=|\bonpopstate\s*=|\bonresize\s*=|\bonstorage\s*=|\bonunload\s*=|\bonblur\s*=|\bonchange\s*=|\boncontextmenu\s*=|\bonfocus\s*=|\boninput\s*=|\boninvalid\s*=|\bonreset\s*=|\bonsearch\s*=|\bonselect\s*=|\bonsubmit\s*=|\bonkeydown\s*=|\bonkeypress\s*=|\bonkeyup\s*=|\bonclick\s*=|\bondblclick\s*=|\bonmousedown\s*=|\bonmousemove\s*=|\bonmouseout\s*=|\bonmouseover\s*=|\bonmouseup\s*=|\bonmousewheel\s*=|\bonwheel\s*=|\bondrag\s*=|\bondragend\s*=|\bondragenter\s*=|\bondragleave\s*=|\bondragover\s*=|\bondragstart\s*=|\bondrop\s*=|\bonscroll\s*=|\boncopy\s*=|\boncut\s*=|\bonpaste\s*=)" \
    "phase:1,deny,status:403,id:12002,msg:'XSS attack detected - event handlers',tag:'attack-xss'"

# Rule 3: HTML tags with attributes
SecRule ARGS|ARGS_NAMES|REQUEST_BODY|REQUEST_HEADERS "@rx (?i)(<img[^>]*>|<iframe[^>]*>|<embed[^>]*>|<object[^>]*>|<link[^>]*>|<meta[^>]*>|<form[^>]*>|<input[^>]*>|<button[^>]*>|<select[^>]*>|<textarea[^>]*>|<svg[^>]*>|<math[^>]*>)" \
    "chain,phase:1,deny,status:403,id:12003,msg:'XSS attack detected - HTML tags',tag:'attack-xss'"
SecRule MATCHED_VAR "@rx (?i)(src\s*=|href\s*=|data\s*=|action\s*=|on\w+\s*=)" 

# Rule 4: Encoded XSS attempts
SecRule ARGS|ARGS_NAMES|REQUEST_BODY|REQUEST_HEADERS "@rx (?i)(&lt;script|&#x3C;script|%3Cscript|javascript&colon;|&#x6A;avascript|&amp;alert)" \
    "phase:1,deny,status:403,id:12004,msg:'XSS attack detected - encoded payload',tag:'attack-xss'"

# Rule 5: Specific search input validation
SecRule ARGS:q "@rx ([<>]|on\w+\s*=)" \
    "chain,phase:1,deny,status:400,id:12005,msg:'XSS in search query detected',tag:'attack-xss',tag:'search'"
SecRule REQUEST_FILENAME "@rx /rest/products/search"

# ===== WEB SOCKET/SOCKET.IO PROTECTION =====
SecRule REQUEST_URI "@beginsWith /socket.io" \
    "id:5000,phase:1,pass,nolog,\
    ctl:ruleRemoveTargetById=920420;REQUEST_HEADERS:Content-Type,\
    ctl:ruleRemoveTargetById=920350;REQUEST_HEADERS:Host,\
    ctl:ruleRemoveById=949110,\
    setvar:tx.socket_io=1"

# WebSocket XSS Protection
SecRule TX:SOCKET_IO "@eq 1" \
    "chain,phase:2,id:5001,deny,status:403,msg:'WebSocket XSS detected',tag:'attack-xss',tag:'websocket'"
SecRule REQUEST_BODY "@rx (?i)(<script[^>]*>|</script>|javascript:|on\w+\s*=|\balert\s*\(|eval\s*\(|document\.)" 

# WebSocket SQL Injection Protection  
SecRule TX:SOCKET_IO "@eq 1" \
    "chain,phase:2,id:5002,deny,status:403,msg:'WebSocket SQL Injection detected',tag:'attack-sqli',tag:'websocket'"
SecRule REQUEST_BODY "@rx (?i)(union\s+select|or\s+1=1|drop\s+table|sleep\s*\(\s*\d+\s*|insert\s+into|update\s+\w+\s+set|delete\s+from)" 

# ===== SQL INJECTION PROTECTION =====
SecRule ARGS|ARGS_NAMES|REQUEST_BODY|REQUEST_HEADERS "@rx (?i)(union\s+select|or\s+['\" ]?1=1|drop\s+table|sleep\s*\(\s*\d+\s*|insert\s+into|update\s+\w+\s+set|delete\s+from|benchmark\s*\(|waitfor\s+delay)" \
    "phase:1,deny,status:403,id:11001,msg:'SQL Injection detected',tag:'attack-sqli'"

# ===== DIRECTORY TRAVERSAL PROTECTION =====
SecRule REQUEST_FILENAME|ARGS|ARGS_NAMES "@rx (\.\./|\.\.\\|/etc/passwd|/etc/shadow|/windows/win\.ini|\\windows\\win\.ini|/ftp)" \
    "phase:1,deny,status:403,id:13001,msg:'Path traversal detected',tag:'attack-traversal'"

# ===== COMMAND INJECTION PROTECTION =====
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx ([|&;`]\s*(rm\s+-rf|wget\s+|curl\s+|bash\s*$|sh\s*$|nc\s+|python\s+-c|perl\s+-e|cmd\.exe|powershell))" \
    "phase:1,deny,status:403,id:14001,msg:'Command injection detected',tag:'attack-cmd'"

# ===== BRUTE FORCE PROTECTION =====
SecRule IP:BF_COUNTER "@gt 10" \
    "phase:1,deny,status:429,id:15001,msg:'Brute force attack detected',tag:'attack-bruteforce',setvar:IP.BF_BLOCKED=1,expirevar:IP.BF_BLOCKED=3600"

SecRule REQUEST_FILENAME "@rx /rest/user/(login|reset)" \
    "phase:1,pass,id:15002,msg:'Login attempt',setvar:IP.BF_COUNTER=+1,expirevar:IP.BF_COUNTER=300"

# ===== SENSITIVE DATA LEAKAGE PROTECTION =====
SecRule RESPONSE_BODY "@rx (?i)(\"password\"\s*:\s*\"[^\"]{6,}\"|\"token\"\s*:\s*\"[^\"]{10,}\"|\"apiKey\"\s*:\s*\"[^\"]+\"|\"secret\"\s*:\s*\"[^\"]+\")" \
    "phase:4,deny,status:500,id:16001,msg:'Sensitive data leakage detected',tag:'data-leakage'"

# ===== RESPONSE XSS DETECTION =====
SecRule RESPONSE_BODY "@rx <script[^>]*>.*?</script>" \
    "phase:4,deny,status:500,id:16002,msg:'XSS in response detected',tag:'xss-response'"

SecRule RESPONSE_BODY "@rx on\w+\s*=\"[^\"]*\"" \
    "phase:4,deny,status:500,id:16003,msg:'Dangerous HTML attributes in response',tag:'xss-response'"

# ===== JUICE SHOP SPECIFIC RULES =====
# Allow search but with XSS protection
SecRule REQUEST_FILENAME "@rx ^/rest/(basket|products)/" \
    "phase:1,pass,id:24002,msg:'Juice Shop API',\
    ctl:ruleRemoveTargetById=911100;REQUEST_METHOD"

# Feedback API - more permissive for learning
SecRule REQUEST_FILENAME "@streq /api/Feedbacks" \
    "phase:1,pass,id:24003,msg:'Feedback API',\
    ctl:ruleRemoveById=12001,\
    ctl:ruleRemoveById=11001"

# Allow Authorization header for API
SecRule REQUEST_FILENAME "@rx ^/api/" \
    "phase:1,pass,id:24005,msg:'Allow Authorization header',\
    ctl:ruleRemoveTargetById=920280;REQUEST_HEADERS:Authorization"

# ===== PERFORMANCE OPTIMIZATION =====
SecRule REQUEST_FILENAME "@rx \.(css|js|png|jpg|jpeg|gif|ico|woff|woff2|ttf|eot|svg)$" \
    "phase:1,pass,id:30001,msg:'Static file',\
    ctl:ruleEngine=Off"
`

	return rules
}

func logError(error types.MatchedRule) {
	log.Printf("Coraza Error: [%s] %s", error.Rule().ID(), error.ErrorLog())
}

func (p *CorazaProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	clientIP := p.getClientIP(r)

	// Check brute force protection
	if p.isBruteForceBlocked(clientIP) {
		p.logger.Warn("Brute force blocked request",
			zap.String("ip", clientIP),
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path))
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	// Update brute force counter for login attempts
	if strings.Contains(r.URL.Path, "/rest/user/login") || strings.Contains(r.URL.Path, "/rest/user/reset") {
		p.incrementBruteForceCounter(clientIP)
	}

	// Process request through Coraza WAF
	tx := p.waf.NewTransaction()
	defer func() {
		if err := tx.ProcessLogging(); err != nil {
			p.logger.Error("Failed to process transaction logging", zap.Error(err))
		}
		tx.Close()
	}()

	// Process request headers
	for key, values := range r.Header {
		for _, value := range values {
			tx.AddRequestHeader(key, value)
		}
	}

	// Process request body if present
	if r.Body != nil {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			p.logger.Error("Failed to read request body", zap.Error(err))
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		r.Body = io.NopCloser(bytes.NewBuffer(body))

		if _, err := tx.RequestBodyWriter().Write(body); err != nil {
			p.logger.Error("Failed to write request body to WAF", zap.Error(err))
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	}

	// Process URI and method
	if _, err := tx.ProcessRequestURI(r.URL.String()); err != nil {
		p.logger.Error("Failed to process request URI", zap.Error(err))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if _, err := tx.ProcessRequestMethod(r.Method); err != nil {
		p.logger.Error("Failed to process request method", zap.Error(err))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Process connection information
	if _, err := tx.ProcessConnection(clientIP, 0, "", 0); err != nil {
		p.logger.Error("Failed to process connection info", zap.Error(err))
	}

	// Check if request was interrupted (blocked)
	if tx.Interruption() != nil {
		p.logger.Warn("Request blocked by WAF",
			zap.String("ip", clientIP),
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.String("rule_id", tx.Interruption().RuleID()),
			zap.String("reason", tx.Interruption().Reason()))
		
		http.Error(w, tx.Interruption().Reason(), tx.Interruption().Status())
		return
	}

	// If request passed WAF, proxy to backend
	p.reverseProxy.ServeHTTP(w, r)
}

func (p *CorazaProxy) modifyResponse(res *http.Response) error {
	// For response body inspection, we need to read and process the response
	// This is a simplified version - in production you'd want more sophisticated handling
	
	// Check content type for text-based responses
	contentType := res.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/html") || strings.Contains(contentType, "application/json") {
		body, err := io.ReadAll(res.Body)
		if err != nil {
			return err
		}
		res.Body.Close()

		// Simple response body checks (simplified)
		if p.detectResponseXSS(body) {
			p.logger.Warn("XSS detected in response")
			// You could block the response here if needed
		}

		if p.detectSensitiveData(body) {
			p.logger.Warn("Sensitive data detected in response")
			// You could block or modify the response here
		}

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
	// Check for X-Forwarded-For header first
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		ips := strings.Split(forwarded, ",")
		return strings.TrimSpace(ips[0])
	}
	
	// Fall back to RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// Brute force protection methods
func (p *CorazaProxy) isBruteForceBlocked(ip string) bool {
	p.cleanupBruteForceCounters()
	
	if counter, exists := p.bruteForceMap[ip]; exists {
		if counter.Blocked && time.Now().Before(counter.BlockUntil) {
			return true
		}
		if counter.Count > 10 && !counter.Blocked {
			counter.Blocked = true
			counter.BlockUntil = time.Now().Add(1 * time.Hour)
			return true
		}
	}
	return false
}

func (p *CorazaProxy) incrementBruteForceCounter(ip string) {
	now := time.Now()
	
	if counter, exists := p.bruteForceMap[ip]; exists {
		// Reset counter if last attempt was more than 5 minutes ago
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
			Blocked:  false,
		}
	}
}

func (p *CorazaProxy) cleanupBruteForceCounters() {
	now := time.Now()
	for ip, counter := range p.bruteForceMap {
		// Remove counters that haven't been seen for over 10 minutes and aren't blocked
		if !counter.Blocked && now.Sub(counter.LastSeen) > 10*time.Minute {
			delete(p.bruteForceMap, ip)
		}
		// Remove blocked counters after block period expires
		if counter.Blocked && now.After(counter.BlockUntil) {
			delete(p.bruteForceMap, ip)
		}
	}
}

// Simplified response body checks
func (p *CorazaProxy) detectResponseXSS(body []byte) bool {
	patterns := []string{
		`<script[^>]*>.*?</script>`,
		`on\w+\s*=\s*"[^"]*"`,
		`javascript:`,
	}
	
	for _, pattern := range patterns {
		if matched, _ := regexp.Match(pattern, body); matched {
			return true
		}
	}
	return false
}

func (p *CorazaProxy) detectSensitiveData(body []byte) bool {
	patterns := []string{
		`"password"\s*:\s*"[^"]{6,}"`,
		`"token"\s*:\s*"[^"]{10,}"`,
		`"apiKey"\s*:\s*"[^"]+"`,
		`"secret"\s*:\s*"[^"]+"`,
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