package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
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
	Count      int
	LastSeen   time.Time
	Blocked    bool
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

# ===== XSS PROTECTION =====
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx <script" "phase:1,deny,status:403,id:1001,msg:'XSS detected'"
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx javascript:" "phase:1,deny,status:403,id:1002,msg:'XSS detected'"
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx onerror=" "phase:1,deny,status:403,id:1003,msg:'XSS detected'"
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx %3Cimg" "phase:1,deny,status:403,id:1004,msg:'URL-encoded XSS detected'"
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx alert\\\(" "phase:1,deny,status:403,id:1005,msg:'XSS detected'"

# ===== SQL INJECTION PROTECTION =====
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx union.*select" "phase:1,deny,status:403,id:2001,msg:'SQLi detected'"
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx or.*1=1" "phase:1,deny,status:403,id:2002,msg:'SQLi detected'"

# ===== PATH TRAVERSAL PROTECTION =====
SecRule REQUEST_FILENAME|ARGS|ARGS_NAMES "@rx \\.\\./" "phase:1,deny,status:403,id:3001,msg:'Path traversal detected'"

# ===== COMMAND INJECTION PROTECTION =====
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx \\|.*rm" "phase:1,deny,status:403,id:4001,msg:'Command injection detected'"

# ===== FTP BLOCKING =====
SecRule REQUEST_URI "@beginsWith /ftp" "phase:1,deny,status:403,id:5001,msg:'FTP access blocked'"

# ===== WEB SOCKET PROTECTION =====
SecRule REQUEST_URI "@beginsWith /socket.io" "id:6001,phase:1,pass,nolog,setvar:tx.socket_io=1"
SecRule TX:SOCKET_IO "@eq 1" "chain,phase:2,id:6002,deny,status:403,msg:'WebSocket XSS detected'"
SecRule REQUEST_BODY "@rx %3Cimg|onerror=|alert\\\("

# ===== SEARCH ENDPOINT PROTECTION =====
SecRule REQUEST_FILENAME "@rx /rest/products/search" "chain,phase:1,deny,status:403,id:7001,msg:'XSS in search API'"
SecRule ARGS:q "@rx %3Cimg|onerror=|alert\\\("

# ===== STATIC FILES =====
SecRule REQUEST_FILENAME "@rx \\.(css|js|png|jpg|jpeg|gif|ico|woff|ttf)$" "phase:1,pass,id:8001,ctl:ruleEngine=Off"
`
	return rules
}

func (p *CorazaProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	clientIP := p.getClientIP(r)

	// Детальное логирование для отладки
	p.logger.Debug("Incoming request",
		zap.String("ip", clientIP),
		zap.String("method", r.Method),
		zap.String("path", r.URL.Path),
		zap.String("query", r.URL.RawQuery),
		zap.String("fragment", r.URL.Fragment))

	// Обработка страницы блокировки
	if r.URL.Path == "/blocked" {
		p.handleBlockedPage(w, r)
		return
	}

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

	// WebSocket detection and protection
	if p.isWebSocketRequest(r) {
		if p.detectXSSInWebSocket(r) {
			p.logger.Warn("XSS in WebSocket blocked",
				zap.String("ip", clientIP),
				zap.String("path", r.URL.Path))
			http.Error(w, "XSS attack detected", http.StatusForbidden)
			return
		}
		p.reverseProxy.ServeHTTP(w, r)
		return
	}

	// XSS detection in URL and parameters
	if p.detectXSSInURL(r) || p.detectXSSInRequest(r) {
		p.logger.Warn("XSS attack blocked",
			zap.String("ip", clientIP),
			zap.String("url", r.URL.String()))
		http.Error(w, "XSS attack detected", http.StatusForbidden)
		return
	}

	// WAF processing
	tx := p.waf.NewTransaction()
	defer tx.Close()

	// Process request through WAF
	tx.ProcessURI(r.URL.String(), r.Method, r.Proto)
	for key, values := range r.Header {
		for _, value := range values {
			tx.AddRequestHeader(key, value)
		}
	}
	tx.ProcessRequestHeaders()

	// Process request body for API endpoints
	if r.Body != nil && (strings.Contains(r.URL.Path, "/api/") || strings.Contains(r.URL.Path, "/rest/")) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			p.logger.Error("Failed to read body", zap.Error(err))
			http.Error(w, "Internal Error", http.StatusInternalServerError)
			return
		}
		r.Body = io.NopCloser(bytes.NewBuffer(body))

		if len(body) > 0 && p.detectAttackInBody(body) {
			p.logger.Warn("Attack detected in request body",
				zap.String("ip", clientIP),
				zap.String("path", r.URL.Path))
			http.Error(w, "Request blocked by security rules", http.StatusForbidden)
			return
		}
	}

	// Check if request was blocked by WAF
	if it := tx.Interruption(); it != nil {
		p.logger.Warn("Request blocked by WAF",
			zap.String("ip", clientIP),
			zap.String("path", r.URL.Path),
			zap.Int("status", it.Status),
			zap.Int("rule_id", it.RuleID))
		http.Error(w, fmt.Sprintf("Request blocked by security rule %d", it.RuleID), it.Status)
		return
	}

	// Proxy to backend
	p.reverseProxy.ServeHTTP(w, r)
}

func (p *CorazaProxy) isWebSocketRequest(r *http.Request) bool {
	return strings.Contains(r.URL.Path, "/socket.io/") ||
		strings.EqualFold(r.Header.Get("Upgrade"), "websocket") ||
		(strings.Contains(r.Header.Get("Connection"), "Upgrade") &&
			strings.EqualFold(r.Header.Get("Upgrade"), "websocket"))
}

func (p *CorazaProxy) detectXSSInWebSocket(r *http.Request) bool {
	fullURL := r.URL.String()
	if p.isXSSPayload(fullURL) {
		return true
	}

	for _, values := range r.URL.Query() {
		for _, value := range values {
			if p.isXSSPayload(value) {
				return true
			}
		}
	}

	for _, values := range r.Header {
		for _, value := range values {
			if p.isXSSPayload(value) {
				return true
			}
		}
	}

	return false
}

func (p *CorazaProxy) detectXSSInURL(r *http.Request) bool {
	fullURL := r.URL.String()

	if fragment := r.URL.Fragment; fragment != "" {
		if decoded, err := url.QueryUnescape(fragment); err == nil && p.isXSSPayload(decoded) {
			return true
		}
		if p.isXSSPayload(fragment) {
			return true
		}
	}

	return p.isXSSPayload(fullURL)
}

func (p *CorazaProxy) detectXSSInRequest(r *http.Request) bool {
	for _, values := range r.URL.Query() {
		for _, value := range values {
			if p.isXSSPayload(value) {
				return true
			}
		}
	}

	if r.Method == "POST" || r.Method == "PUT" {
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
		"<script", "</script>", "javascript:", "vbscript:",
		"onerror=", "onload=", "onclick=", "alert(",
		"<img", "<svg", "<iframe", "<embed",
		"%3Cimg", "%3Cscript", "onerror%3D", "alert%28",
		"&lt;script", "&lt;img", "src=x", "onerror=alert",
	}

	inputLower := strings.ToLower(input)
	for _, pattern := range xssPatterns {
		if strings.Contains(inputLower, pattern) {
			return true
		}
	}
	return false
}

func (p *CorazaProxy) detectAttackInBody(body []byte) bool {
	patterns := []string{
		`<script`, `javascript:`, `onerror=`, `union.*select`, `\.\./`,
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
	contentType := res.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/html") {
		body, err := io.ReadAll(res.Body)
		if err != nil {
			return err
		}
		res.Body.Close()

		html := string(body)
		if strings.Contains(html, "</body>") {
			xssScript := `
<script>
// Client-side XSS Protection
(function() {
    const checkFragment = function() {
        const fragment = window.location.hash;
        const patterns = ['%3Cimg', 'onerror=', 'alert(', '<script', 'javascript:'];
        for (const pattern of patterns) {
            if (fragment.includes(pattern)) {
                window.location.href = '/blocked?reason=xss_fragment';
                return true;
            }
        }
        return false;
    };
    
    if (checkFragment()) return;
    window.addEventListener('hashchange', checkFragment);
})();
</script>
</body>`
			html = strings.Replace(html, "</body>", xssScript, 1)
		}

		res.Body = io.NopCloser(bytes.NewBufferString(html))
		res.ContentLength = int64(len(html))
		res.Header.Set("Content-Length", strconv.Itoa(len(html)))
	}
	return nil
}

func (p *CorazaProxy) handleBlockedPage(w http.ResponseWriter, r *http.Request) {
	reason := r.URL.Query().Get("reason")
	message := "Access blocked"

	if reason == "xss_fragment" {
		message = "XSS attack detected in URL"
	}

	html := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <title>Access Blocked</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
        .blocked { color: #d32f2f; font-size: 24px; margin-bottom: 20px; }
        .message { margin: 20px 0; }
    </style>
</head>
<body>
    <div class="blocked">🚫 %s</div>
    <div class="message">Your request has been blocked by the security system.</div>
    <a href="/">Return to home page</a>
</body>
</html>`, message)

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte(html))
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
		if (!counter.Blocked && now.Sub(counter.LastSeen) > 10*time.Minute) ||
			(counter.Blocked && now.After(counter.BlockUntil)) {
			delete(p.bruteForceMap, ip)
		}
	}
}

func main() {
	backendURL := "http://192.168.0.185:3000"
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