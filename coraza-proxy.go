package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/corazawaf/coraza/v3"
	txhttp "github.com/corazawaf/coraza/v3/http"
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

# XSS Protection
SecRule ARGS|ARGS_NAMES|REQUEST_BODY|REQUEST_URI "@rx <script" \
    "phase:1,deny,status:403,id:1001,msg:'XSS detected'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx javascript:" \
    "phase:1,deny,status:403,id:1002,msg:'XSS detected'"

# SQL Injection Protection
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx union.*select" \
    "phase:1,deny,status:403,id:2001,msg:'SQLi detected'"

# Path Traversal
SecRule REQUEST_FILENAME|ARGS|ARGS_NAMES "@rx \\.\\./" \
    "phase:1,deny,status:403,id:3001,msg:'Path traversal detected'"

# FTP Access Block
SecRule REQUEST_URI "@beginsWith /ftp" \
    "phase:1,deny,status:403,id:4001,msg:'FTP access blocked'"

# Static Files - No Inspection
SecRule REQUEST_FILENAME "@rx \\.(css|js|png|jpg|jpeg|gif|ico)$" \
    "phase:1,pass,id:5001,ctl:ruleEngine=Off"
`

	return rules
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
	if counter, exists := p.bruteForceMap[ip]; exists {
		if counter.Blocked && time.Now().Before(counter.BlockUntil) {
			return true
		}
		if time.Since(counter.LastSeen) > 5*time.Minute {
			counter.Count = 0
		}
		if counter.Count >= 15 {
			counter.Blocked = true
			counter.BlockUntil = time.Now().Add(30 * time.Minute)
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
	for {
		time.Sleep(5 * time.Minute)
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
// XSS Protection for URL fragments
(function() {
    const checkFragment = function() {
        const fragment = window.location.hash;
        if (fragment && (
            fragment.includes('<script') || 
            fragment.includes('onerror=') ||
            fragment.includes('alert(') ||
            fragment.includes('javascript:')
        )) {
            window.location.href = '/blocked?reason=xss_fragment';
            return true;
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

func (p *CorazaProxy) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	p.logger.Error("Proxy error", zap.Error(err))
	http.Error(w, "Bad Gateway", http.StatusBadGateway)
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
        .blocked { color: #d32f2f; font-size: 24px; }
    </style>
</head>
<body>
    <div class="blocked">🚫 %s</div>
    <p>Your request has been blocked by the security system.</p>
    <a href="/">Return to home page</a>
</body>
</html>
`, message)
	
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte(html))
}

func (p *CorazaProxy) TestRules() {
	fmt.Println("=== Testing Coraza Rules ===")
	
	testCases := []struct {
		name     string
		url      string
		expected int
	}{
		{"XSS in URL", "/search?q=<script>alert()</script>", 403},
		{"SQL Injection", "/login?user=union select 1,2,3", 403},
		{"Path Traversal", "/files/../../../etc/passwd", 403},
		{"FTP Access", "/ftp/files", 403},
		{"Normal Request", "/api/data", 200},
		{"Static File", "/style.css", 200},
	}

	for _, tc := range testCases {
		req := httptest.NewRequest("GET", tc.url, nil)
		rr := httptest.NewRecorder()
		
		p.ServeHTTP(rr, req)
		
		status := rr.Code
		result := "✓"
		if status != tc.expected {
			result = "✗"
		}
		
		fmt.Printf("%s %s: %d (expected %d) %s\n", 
			result, tc.name, status, tc.expected, tc.url)
	}
}

func (p *CorazaProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// WAF status endpoint
	if r.URL.Path == "/waf-status" {
		p.showWAFStatus(w, r)
		return
	}

	if r.URL.Path == "/blocked" {
		p.handleBlockedPage(w, r)
		return
	}

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

	// Use Coraza HTTP wrapper for proper transaction handling
	tx := p.waf.NewTransaction()
	defer tx.Close()

	// Process using Coraza HTTP helpers
	if _, err := txhttp.Wrap(tx, r, p.reverseProxy).ServeHTTP(w, r); err != nil {
		p.logger.Error("Error processing request", zap.Error(err))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func (p *CorazaProxy) showWAFStatus(w http.ResponseWriter, r *http.Request) {
	html := `
<!DOCTYPE html>
<html>
<head>
    <title>WAF Status</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .status { padding: 10px; margin: 10px 0; border-radius: 5px; }
        .active { background: #d4edda; border: 1px solid #c3e6cb; }
        .rules { background: #fff3cd; border: 1px solid #ffeaa7; }
    </style>
</head>
<body>
    <h1>WAF Status</h1>
    <div class="status active">
        <h3>✅ WAF is Active</h3>
        <p>Coraza Web Application Firewall is running and protecting your application.</p>
    </div>
    <div class="status rules">
        <h3>📋 Active Rules:</h3>
        <ul>
            <li>XSS Protection (Rules 1001-1002)</li>
            <li>SQL Injection Protection (Rule 2001)</li>
            <li>Path Traversal Protection (Rule 3001)</li>
            <li>FTP Access Blocking (Rule 4001)</li>
            <li>Static Files Bypass (Rule 5001)</li>
        </ul>
    </div>
</body>
</html>`
	
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
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

	// Test rules on startup
	proxy.TestRules()

	port := "8090"
	if len(os.Args) > 2 {
		port = os.Args[2]
	}

	log.Printf("Starting Coraza proxy on port %s, forwarding to %s", port, backendURL)
	log.Fatal(http.ListenAndServe(":"+port, proxy))
}