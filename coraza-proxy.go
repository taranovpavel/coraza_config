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
	"strings"
	"strconv"
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

# XSS Protection
SecRule ARGS|ARGS_NAMES|REQUEST_BODY|REQUEST_URI "@detectXSS" \
    "phase:1,deny,status:403,id:1000,msg:'XSS attack detected',tag:'attack-xss'"

# SQL Injection Protection
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@detectSQLi" \
    "phase:1,deny,status:403,id:2000,msg:'SQL injection detected',tag:'attack-sqli'"

# Path Traversal
SecRule ARGS|ARGS_NAMES|REQUEST_FILENAME "@rx \\.\\.(/|%2f)" \
    "phase:1,deny,status:403,id:3000,msg:'Path traversal detected',tag:'attack-traversal'"

# Command Injection
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx [;&|` + "`" + `]\s*(rm|wget|curl|bash|sh)" \
    "phase:1,deny,status:403,id:4000,msg:'Command injection detected',tag:'attack-cmd'"

# FTP Access Block
SecRule REQUEST_URI "@rx ^/ftp(/|$)" \
    "phase:1,deny,status:403,id:5000,msg:'FTP access blocked',tag:'block-ftp'"

# Static Files - No Inspection
SecRule REQUEST_FILENAME "@rx \\.(css|js|png|jpg|jpeg|gif|ico|woff|woff2)$" \
    "phase:1,pass,id:6000,ctl:ruleEngine=Off"

# Brute Force Detection
SecRule REQUEST_URI "@streq /rest/user/login" \
    "phase:1,pass,id:7000,setvar:TX.brute_force_counter=+1,expirevar:TX.brute_force_counter=300"

SecRule TX:brute_force_counter "@gt 10" \
    "phase:1,deny,status:429,id:7001,msg:'Brute force attack detected',tag:'attack-bruteforce'"
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
	if r.URL.Path == "/rest/user/login" {
		p.incrementBruteForceCounter(clientIP)
	}

	// Create transaction
	tx := p.waf.NewTransaction()
	defer tx.Close()

	// Process request
	tx.ProcessURI(r.URL.String(), r.Method, r.Proto)
	
	for key, values := range r.Header {
		for _, value := range values {
			tx.AddRequestHeader(key, value)
		}
	}
	tx.ProcessRequestHeaders()

	// Process body only for API endpoints
	if r.Body != nil && (strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/rest/")) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			p.logger.Error("Failed to read body", zap.Error(err))
			http.Error(w, "Internal Error", http.StatusInternalServerError)
			return
		}
		r.Body = io.NopCloser(bytes.NewBuffer(body))
		
		if _, err := tx.RequestBodyWriter().Write(body); err != nil {
			p.logger.Error("Failed to process body", zap.Error(err))
		}
		tx.ProcessRequestBody()
	}

	// Check if blocked
	if it := tx.Interruption(); it != nil {
		p.logger.Warn("Request blocked by WAF",
			zap.String("ip", clientIP),
			zap.String("path", r.URL.Path),
			zap.Int("status", it.Status),
			zap.Int("rule_id", it.RuleID),
			zap.String("msg", it.Message))
		
		if it.Status == 429 {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		} else {
			http.Error(w, "Request blocked by security rules", it.Status)
		}
		return
	}

	// Proxy to backend
	p.reverseProxy.ServeHTTP(w, r)
}

func (p *CorazaProxy) isBruteForceBlocked(ip string) bool {
	if counter, exists := p.bruteForceMap[ip]; exists {
		if counter.Blocked && time.Now().Before(counter.BlockUntil) {
			return true
		}
		// Сбрасываем счетчик если прошло больше 5 минут
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