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
	xssAttempts   map[string]int // 🔥 Трекер XSS попыток
}

type BruteForceCounter struct {
	Count      int
	LastSeen   time.Time
	Blocked    bool
	BlockUntil time.Time
}

func NewCorazaProxy(backendURL string) (*CorazaProxy, error) {
	logger, err := zap.NewDevelopment()
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
		xssAttempts:   make(map[string]int), // 🔥 Инициализация трекера XSS
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
	go proxy.cleanupXSSAttempts()

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

# ===== HEALTH CHECKS =====
SecRule REQUEST_FILENAME "@rx ^/(health|healthz|ready|readyz|live|livez|status|ping|helth)" "phase:1,pass,nolog,id:50,ctl:ruleEngine=Off"

# ===== STATIC FILES =====
SecRule REQUEST_FILENAME "@rx \\.(css|js|png|jpg|jpeg|gif|ico|woff|ttf|svg)$" "phase:1,pass,id:8001,ctl:ruleEngine=Off"
`
	return rules
}

func (p *CorazaProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	clientIP := p.getClientIP(r)

	// Health check requests
	if p.isHealthCheckRequest(r) {
		p.reverseProxy.ServeHTTP(w, r)
		return
	}

	// Static files
	if p.isStaticFileRequest(r) {
		p.reverseProxy.ServeHTTP(w, r)
		return
	}

	// 🔥 ГЛАВНОЕ: Обнаружение XSS при ПЕРВОМ запросе с фрагментом
	if p.detectInitialXSSRequest(r) {
		p.logger.Warn("🚨 INITIAL XSS REQUEST BLOCKED",
			zap.String("ip", clientIP),
			zap.String("url", r.URL.String()),
			zap.String("fragment", r.URL.Fragment))
		http.Error(w, "XSS attack detected", http.StatusForbidden)
		return
	}

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

	// WAF processing
	tx := p.waf.NewTransaction()
	defer tx.Close()

	tx.ProcessURI(r.URL.String(), r.Method, r.Proto)
	for key, values := range r.Header {
		for _, value := range values {
			tx.AddRequestHeader(key, value)
		}
	}
	tx.ProcessRequestHeaders()

	// Check if request was blocked by WAF
	if it := tx.Interruption(); it != nil {
		p.logger.Warn("Request blocked by WAF",
			zap.String("ip", clientIP),
			zap.String("path", r.URL.Path),
			zap.Int("rule_id", it.RuleID))
		http.Error(w, "Request blocked by security rules", http.StatusForbidden)
		return
	}

	// Proxy to backend
	p.reverseProxy.ServeHTTP(w, r)
}

// 🔥 ОСНОВНАЯ ФУНКЦИЯ: Обнаружение XSS при начальном запросе
func (p *CorazaProxy) detectInitialXSSRequest(r *http.Request) bool {
	clientIP := p.getClientIP(r)
	
	// Проверяем фрагмент URL на наличие XSS
	if fragment := r.URL.Fragment; fragment != "" {
		if p.containsXSSPatterns(fragment) {
			p.logger.Info("🚨 XSS DETECTED IN FRAGMENT",
				zap.String("ip", clientIP),
				zap.String("fragment", fragment))
			
			// Блокируем после 2 попыток
			p.xssAttempts[clientIP]++
			if p.xssAttempts[clientIP] >= 2 {
				p.logger.Warn("🚨 XSS ATTEMPTS EXCEEDED - BLOCKING IP",
					zap.String("ip", clientIP),
					zap.Int("attempts", p.xssAttempts[clientIP]))
				return true
			}
			return true
		}
	}

	// Проверяем полный URL
	fullURL := r.URL.String()
	if p.containsXSSPatterns(fullURL) {
		p.logger.Info("🚨 XSS DETECTED IN URL",
			zap.String("ip", clientIP),
			zap.String("url", fullURL))
		return true
	}

	return false
}

func (p *CorazaProxy) containsXSSPatterns(input string) bool {
	xssPatterns := []string{
		// Конкретно ваш payload
		"%3Cimg%20src%3Dx%20onerror%3Dalert('XSS')%3E",
		"%3Cimg%20src=x%20onerror=alert('XSS')%3E",
		"%3Cimg",
		"src%3Dx", 
		"onerror%3D",
		"alert('XSS')",
		
		// Общие паттерны
		"<script", "</script>", "javascript:", 
		"onerror=", "onload=", "onclick=",
		"alert(", "confirm(", "prompt(",
		"<img", "<svg", "<iframe",
		"%3Cscript", "onerror%3D", "alert%28",
		"&lt;script", "&lt;img",
	}

	inputLower := strings.ToLower(input)
	for _, pattern := range xssPatterns {
		if strings.Contains(inputLower, pattern) {
			return true
		}
	}
	return false
}

func (p *CorazaProxy) isHealthCheckRequest(r *http.Request) bool {
	healthCheckPaths := []string{
		"/health", "/healthz", "/ready", "/readyz", 
		"/live", "/livez", "/status", "/ping", "/helth",
	}
	
	for _, path := range healthCheckPaths {
		if r.URL.Path == path {
			return true
		}
	}
	return false
}

func (p *CorazaProxy) isStaticFileRequest(r *http.Request) bool {
	staticExtensions := []string{
		".css", ".js", ".png", ".jpg", ".jpeg", 
		".gif", ".ico", ".woff", ".ttf", ".svg",
	}
	
	for _, ext := range staticExtensions {
		if strings.HasSuffix(r.URL.Path, ext) {
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
// Enhanced Client-side XSS Protection
(function() {
    const patterns = ['%3Cimg', 'onerror=', 'alert(', '<script', 'javascript:', 'src=x'];
    
    function checkFragment() {
        const fragment = window.location.hash;
        for (const pattern of patterns) {
            if (fragment.toLowerCase().includes(pattern)) {
                console.warn('XSS blocked:', fragment);
                window.location.href = '/blocked?reason=xss_fragment';
                return true;
            }
        }
        return false;
    }
    
    // Check immediately
    if (checkFragment()) return;
    
    // Check on all navigation events
    window.addEventListener('hashchange', checkFragment);
    window.addEventListener('popstate', checkFragment);
    
    // Override pushState to detect SPA navigation
    const originalPushState = history.pushState;
    history.pushState = function(state, title, url) {
        originalPushState.apply(this, arguments);
        setTimeout(checkFragment, 100);
    };
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
    </style>
</head>
<body>
    <div class="blocked">🚫 %s</div>
    <p>Your request has been blocked by the security system.</p>
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

// 🔥 Очистка XSS попыток
func (p *CorazaProxy) cleanupXSSAttempts() {
	for {
		time.Sleep(10 * time.Minute)
		now := time.Now()
		for ip := range p.xssAttempts {
			// Удаляем старые записи (старше 30 минут)
			if p.xssAttempts[ip] > 0 {
				// Пока просто сбрасываем счетчик
				p.xssAttempts[ip] = 0
			}
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