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

SecRuleUpdateTargetById 920280 "!REQUEST_HEADERS:Host"
SecRuleUpdateTargetById 920350 "!REQUEST_HEADERS:Host"
SecRuleUpdateTargetById 920270 "!REQUEST_HEADERS:User-Agent"
SecRuleUpdateTargetById 933151 "!ARGS:email"
SecRuleUpdateTargetById 932150 "!ARGS:email"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY|REQUEST_HEADERS "@rx (?i)(<script[^>]*>|</script>|javascript:|vbscript:|\balert\s*\(|eval\s*\(|document\.(cookie|location|write))" "phase:1,deny,status:403,id:12001,msg:'XSS attack detected',tag:'attack-xss'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY|REQUEST_HEADERS "@rx (?i)(\bon\w+\s*=)" "phase:1,deny,status:403,id:12002,msg:'XSS attack detected - event handlers',tag:'attack-xss'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY|REQUEST_HEADERS "@rx (?i)(<img[^>]*>|<iframe[^>]*>|<embed[^>]*>|<object[^>]*>)" "chain,phase:1,deny,status:403,id:12003,msg:'XSS attack detected - HTML tags',tag:'attack-xss'"
SecRule MATCHED_VAR "@rx (?i)(src\s*=|href\s*=|on\w+\s*=)"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY|REQUEST_HEADERS "@rx (?i)(&lt;script|%3Cscript|javascript&colon;)" "phase:1,deny,status:403,id:12004,msg:'XSS attack detected - encoded payload',tag:'attack-xss'"

SecRule ARGS:q "@rx ([<>]|on\w+\s*=)" "chain,phase:1,deny,status:400,id:12005,msg:'XSS in search query',tag:'attack-xss'"
SecRule REQUEST_FILENAME "@rx /rest/products/search"

SecRule REQUEST_URI "@beginsWith /socket.io" "id:5000,phase:1,pass,nolog,setvar:tx.socket_io=1"

SecRule TX:SOCKET_IO "@eq 1" "chain,phase:2,id:5001,deny,status:403,msg:'WebSocket XSS detected',tag:'websocket'"
SecRule REQUEST_BODY "@rx (?i)(<script|javascript:|on\w+\s*=|\balert\s*\()"

SecRule TX:SOCKET_IO "@eq 1" "chain,phase:2,id:5002,deny,status:403,msg:'WebSocket SQL Injection',tag:'websocket'"
SecRule REQUEST_BODY "@rx (?i)(union\s+select|or\s+1=1|drop\s+table)"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY|REQUEST_HEADERS "@rx (?i)(union\s+select|or\s+1=1|drop\s+table|sleep\s*\(\s*\d+\s*)" "phase:1,deny,status:403,id:11001,msg:'SQL Injection detected',tag:'attack-sqli'"

SecRule REQUEST_FILENAME|ARGS|ARGS_NAMES "@rx (\.\./|\.\.\\|/etc/passwd)" "phase:1,deny,status:403,id:13001,msg:'Path traversal detected',tag:'attack-traversal'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx ([|&;]\s*(rm\s+-rf|wget\s+|curl\s+|bash\s*$))" "phase:1,deny,status:403,id:14001,msg:'Command injection detected',tag:'attack-cmd'"

SecRule IP:BF_COUNTER "@gt 10" "phase:1,deny,status:429,id:15001,msg:'Brute force attack',tag:'attack-bruteforce'"

SecRule REQUEST_FILENAME "@rx /rest/user/(login|reset)" "phase:1,pass,id:15002,msg:'Login attempt',setvar:IP.BF_COUNTER=+1"

SecRule RESPONSE_BODY "@rx (?i)(\"password\"\s*:\s*\"[^\"]{6,}\"|\"token\"\s*:\s*\"[^\"]{10,}\")" "phase:4,deny,status:500,id:16001,msg:'Sensitive data leakage',tag:'data-leakage'"

SecRule RESPONSE_BODY "@rx <script[^>]*>.*?</script>" "phase:4,deny,status:500,id:16002,msg:'XSS in response',tag:'xss-response'"

SecRule REQUEST_FILENAME "@rx ^/rest/(basket|products)/" "phase:1,pass,id:24002,msg:'Juice Shop API'"

SecRule REQUEST_FILENAME "@streq /api/Feedbacks" "phase:1,pass,id:24003,msg:'Feedback API'"

SecRule REQUEST_FILENAME "@rx \.(css|js|png|jpg|jpeg|gif|ico)$" "phase:1,pass,id:30001,ctl:ruleEngine=Off"
`

	return rules
}

func logError(error types.MatchedRule) {
	log.Printf("Coraza Error: [%s] %s", error.Rule().ID(), error.ErrorLog())
}

func (p *CorazaProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	clientIP := p.getClientIP(r)

	if p.isBruteForceBlocked(clientIP) {
		p.logger.Warn("Brute force blocked", zap.String("ip", clientIP))
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	if strings.Contains(r.URL.Path, "/rest/user/login") {
		p.incrementBruteForceCounter(clientIP)
	}

	tx := p.waf.NewTransaction()
	defer tx.Close()

	for key, values := range r.Header {
		for _, value := range values {
			tx.AddRequestHeader(key, value)
		}
	}

	if r.Body != nil {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			p.logger.Error("Failed to read body", zap.Error(err))
			http.Error(w, "Internal Error", http.StatusInternalServerError)
			return
		}
		r.Body = io.NopCloser(bytes.NewBuffer(body))
		tx.RequestBodyWriter().Write(body)
	}

	tx.ProcessRequestURI(r.URL.String())
	tx.ProcessRequestMethod(r.Method)
	tx.ProcessConnection(clientIP, 0, "", 0)

	if tx.Interruption() != nil {
		p.logger.Warn("Request blocked",
			zap.String("ip", clientIP),
			zap.String("path", r.URL.Path),
			zap.String("rule", tx.Interruption().RuleID()))
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	p.reverseProxy.ServeHTTP(w, r)
}

func (p *CorazaProxy) modifyResponse(res *http.Response) error {
	contentType := res.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/html") || strings.Contains(contentType, "application/json") {
		body, err := io.ReadAll(res.Body)
		if err != nil {
			return err
		}
		res.Body.Close()

		if p.detectResponseXSS(body) {
			p.logger.Warn("XSS in response")
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

	log.Printf("Starting proxy on :%s -> %s", port, backendURL)
	log.Fatal(http.ListenAndServe(":"+port, proxy))
}