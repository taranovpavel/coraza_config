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
	"context"
	"os/signal"
	"syscall"

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
SecResponseBodyMimeType text/plain text/html text/xml application/json
SecResponseBodyLimit 524288

SecAuditEngine On
SecAuditLog ./coraza_audit.log
SecAuditLogFormat JSON
SecDebugLog ./coraza_debug.log
SecDebugLogLevel 3
SecAuditLogParts "ABIJDEFHZ"

###########################################################################
# OWASP TOP 10 2021 - ИСПРАВЛЕННЫЙ РАБОЧИЙ ВАРИАНТ
###########################################################################

####################################################
# A01:2021 - BROKEN ACCESS CONTROL
####################################################
SecRule REQUEST_METHOD "!@within GET POST HEAD OPTIONS" \
    "phase:1,deny,status:405,id:10100,msg:'OWASP A01: Invalid HTTP method',tag:'OWASP_A01',tag:'access-control'"

SecRule ARGS "@contains ../" \
    "phase:1,deny,status:403,id:10101,msg:'OWASP A01: Path traversal attempt',tag:'OWASP_A01'"

SecRule ARGS "@contains /etc/" \
    "phase:1,deny,status:403,id:10102,msg:'OWASP A01: Path traversal /etc/',tag:'OWASP_A01'"

SecRule ARGS "@contains /proc/" \
    "phase:1,deny,status:403,id:10103,msg:'OWASP A01: Path traversal /proc/',tag:'OWASP_A01'"

SecRule REQUEST_URI "@rx ^/api/(users|admin|settings|orders)" \
    "phase:1,chain,deny,status:403,id:10104,msg:'OWASP A01: Unauthorized API access',tag:'OWASP_A01'"
SecRule &REQUEST_HEADERS:Authorization "@eq 0"

SecRule REQUEST_URI "@beginsWith /socket.io/" \
    "phase:1,pass,id:10106,ctl:ruleRemoveById=10105"

####################################################
# A02:2021 - CRYPTOGRAPHIC FAILURES
####################################################
SecRule REQUEST_PROTOCOL "!@streq HTTP/2" \
    "phase:1,pass,id:10200,msg:'OWASP A02: Non-HTTP/2 protocol',tag:'OWASP_A02'"

SecRule REQUEST_BODY "@contains password" \
    "phase:2,deny,status:400,id:10201,msg:'OWASP A02: Plain text password detected',tag:'OWASP_A02'"

SecRule REQUEST_BODY "@contains api_key" \
    "phase:2,deny,status:400,id:10202,msg:'OWASP A02: API key exposed in body',tag:'OWASP_A02'"
	
SecRule ARGS|REQUEST_BODY "@contains secret=" \
    "phase:2,deny,status:400,id:10203,msg:'OWASP A02: Secret exposed',tag:'OWASP_A02'"

SecRule ARGS|REQUEST_BODY "@contains token=" \
    "phase:2,deny,status:400,id:10204,msg:'OWASP A02: Token exposed',tag:'OWASP_A02'"

####################################################
# A03:2021 - INJECTION
####################################################
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains union select" \
    "phase:2,deny,status:403,id:10301,msg:'OWASP A03: SQLi UNION SELECT',tag:'OWASP_A03',tag:'sqli'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains select from" \
    "phase:2,deny,status:403,id:10302,msg:'OWASP A03: SQLi SELECT FROM',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains insert into" \
    "phase:2,deny,status:403,id:10303,msg:'OWASP A03: SQLi INSERT INTO',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains update set" \
    "phase:2,deny,status:403,id:10304,msg:'OWASP A03: SQLi UPDATE SET',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains delete from" \
    "phase:2,deny,status:403,id:10305,msg:'OWASP A03: SQLi DELETE FROM',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains drop table" \
    "phase:2,deny,status:403,id:10306,msg:'OWASP A03: SQLi DROP TABLE',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains 1=1" \
    "phase:2,deny,status:403,id:10307,msg:'OWASP A03: SQLi OR 1=1',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains --" \
    "phase:2,deny,status:403,id:10308,msg:'OWASP A03: SQL comment',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains /*" \
    "phase:2,deny,status:403,id:10309,msg:'OWASP A03: SQL block comment',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains sleep" \
    "phase:2,deny,status:403,id:10310,msg:'OWASP A03: SQL time-based injection',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains benchmark" \
    "phase:2,deny,status:403,id:10311,msg:'OWASP A03: SQL benchmark injection',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains waitfor" \
    "phase:2,deny,status:403,id:10312,msg:'OWASP A03: SQL Server delay',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains pg_sleep" \
    "phase:2,deny,status:403,id:10313,msg:'OWASP A03: PostgreSQL sleep',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains exec" \
    "phase:2,deny,status:403,id:10314,msg:'OWASP A03: SQL exec command',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains sp_" \
    "phase:2,deny,status:403,id:10315,msg:'OWASP A03: SQL sp_ procedure',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains xp_" \
    "phase:2,deny,status:403,id:10316,msg:'OWASP A03: SQL xp_ procedure',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains <script" \
    "phase:2,deny,status:403,id:10350,msg:'OWASP A03: XSS script tag',tag:'OWASP_A03',tag:'xss'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains javascript:" \
    "phase:2,deny,status:403,id:10351,msg:'OWASP A03: XSS javascript protocol',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains onerror=" \
    "phase:2,deny,status:403,id:10352,msg:'OWASP A03: XSS onerror handler',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains onload=" \
    "phase:2,deny,status:403,id:10353,msg:'OWASP A03: XSS onload handler',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains onclick=" \
    "phase:2,deny,status:403,id:10354,msg:'OWASP A03: XSS onclick handler',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains onmouseover=" \
    "phase:2,deny,status:403,id:10355,msg:'OWASP A03: XSS onmouseover handler',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains alert(" \
    "phase:2,deny,status:403,id:10356,msg:'OWASP A03: XSS alert function',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains confirm(" \
    "phase:2,deny,status:403,id:10357,msg:'OWASP A03: XSS confirm function',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains prompt(" \
    "phase:2,deny,status:403,id:10358,msg:'OWASP A03: XSS prompt function',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains eval(" \
    "phase:2,deny,status:403,id:10359,msg:'OWASP A03: XSS eval function',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains document.cookie" \
    "phase:2,deny,status:403,id:10360,msg:'OWASP A03: XSS cookie theft',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains document.write" \
    "phase:2,deny,status:403,id:10361,msg:'OWASP A03: XSS document.write',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains innerHTML" \
    "phase:2,deny,status:403,id:10362,msg:'OWASP A03: XSS innerHTML',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains outerHTML" \
    "phase:2,deny,status:403,id:10363,msg:'OWASP A03: XSS outerHTML',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains <iframe" \
    "phase:2,deny,status:403,id:10364,msg:'OWASP A03: XSS iframe',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains <embed" \
    "phase:2,deny,status:403,id:10365,msg:'OWASP A03: XSS embed',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains <object" \
    "phase:2,deny,status:403,id:10366,msg:'OWASP A03: XSS object',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains <svg" \
    "phase:2,deny,status:403,id:10367,msg:'OWASP A03: XSS SVG',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains <img src" \
    "phase:2,deny,status:403,id:10368,msg:'OWASP A03: XSS image injection',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains <a href javascript:" \
    "phase:2,deny,status:403,id:10369,msg:'OWASP A03: XSS malicious link',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains expression(" \
    "phase:2,deny,status:403,id:10370,msg:'OWASP A03: XSS CSS expression',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains <link javascript:" \
    "phase:2,deny,status:403,id:10371,msg:'OWASP A03: XSS link injection',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains <meta refresh" \
    "phase:2,deny,status:403,id:10372,msg:'OWASP A03: XSS meta refresh',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains <base href" \
    "phase:2,deny,status:403,id:10373,msg:'OWASP A03: XSS base tag manipulation',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains <form action javascript:" \
    "phase:2,deny,status:403,id:10374,msg:'OWASP A03: XSS form action hijack',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains %3Cscript" \
    "phase:2,deny,status:403,id:10375,msg:'OWASP A03: URL encoded XSS',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains %3Cimg" \
    "phase:2,deny,status:403,id:10376,msg:'OWASP A03: URL encoded img XSS',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains %3Ciframe" \
    "phase:2,deny,status:403,id:10377,msg:'OWASP A03: URL encoded iframe XSS',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains onerror%3D" \
    "phase:2,deny,status:403,id:10378,msg:'OWASP A03: URL encoded onerror',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains alert%28" \
    "phase:2,deny,status:403,id:10379,msg:'OWASP A03: URL encoded alert',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains %253Cscript" \
    "phase:2,deny,status:403,id:10380,msg:'OWASP A03: Double encoded XSS',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains &lt;script" \
    "phase:2,deny,status:403,id:10381,msg:'OWASP A03: HTML entity XSS',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains &lt;img" \
    "phase:2,deny,status:403,id:10382,msg:'OWASP A03: HTML entity img XSS',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains |ls" \
    "phase:2,deny,status:403,id:10400,msg:'OWASP A03: Command injection ls',tag:'OWASP_A03',tag:'cmdi'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains |cat" \
    "phase:2,deny,status:403,id:10401,msg:'OWASP A03: Command injection cat',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains |rm" \
    "phase:2,deny,status:403,id:10402,msg:'OWASP A03: Command injection rm',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains |wget" \
    "phase:2,deny,status:403,id:10403,msg:'OWASP A03: Command injection wget',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains |curl" \
    "phase:2,deny,status:403,id:10404,msg:'OWASP A03: Command injection curl',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains |nc" \
    "phase:2,deny,status:403,id:10405,msg:'OWASP A03: Command injection netcat',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains |bash" \
    "phase:2,deny,status:403,id:10406,msg:'OWASP A03: Command injection bash',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains |sh" \
    "phase:2,deny,status:403,id:10407,msg:'OWASP A03: Command injection sh',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains |python" \
    "phase:2,deny,status:403,id:10408,msg:'OWASP A03: Command injection python',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains |perl" \
    "phase:2,deny,status:403,id:10409,msg:'OWASP A03: Command injection perl',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains |php" \
    "phase:2,deny,status:403,id:10410,msg:'OWASP A03: Command injection php',tag:'OWASP_A03'"

########

SecRule ARGS "@rx ['\"]?\\s*OR\\s*1=1" \
    "phase:2,deny,status:403,id:10320,msg:'OWASP A03: SQLi OR 1=1 pattern in args',tag:'OWASP_A03',tag:'sqli'"

SecRule REQUEST_BODY "@rx ['\"]?\\s*OR\\s*1=1" \
    "phase:2,deny,status:403,id:10321,msg:'OWASP A03: SQLi OR 1=1 pattern in body',tag:'OWASP_A03',tag:'sqli'"

SecRule ARGS "@rx --\\s*$" \
    "phase:2,deny,status:403,id:10322,msg:'OWASP A03: SQL comment in args',tag:'OWASP_A03'"

SecRule REQUEST_BODY "@rx --\\s*$" \
    "phase:2,deny,status:403,id:10323,msg:'OWASP A03: SQL comment in body',tag:'OWASP_A03'"

SecRule ARGS "@rx /\\*" \
    "phase:2,deny,status:403,id:10324,msg:'OWASP A03: SQL block comment in args',tag:'OWASP_A03'"

SecRule REQUEST_BODY "@rx /\\*" \
    "phase:2,deny,status:403,id:10325,msg:'OWASP A03: SQL block comment in body',tag:'OWASP_A03'"

SecRule ARGS "@rx ['\"]\\s*OR\\s*['\"]\\s*=\\s*['\"]" \
    "phase:2,deny,status:403,id:10326,msg:'OWASP A03: SQLi tautology in args',tag:'OWASP_A03'"

SecRule REQUEST_BODY "@rx ['\"]\\s*OR\\s*['\"]\\s*=\\s*['\"]" \
    "phase:2,deny,status:403,id:10327,msg:'OWASP A03: SQLi tautology in body',tag:'OWASP_A03'"

SecRule ARGS "@rx ['\"]?\\s*(?i:or)\\s*1=1" \
    "phase:2,deny,status:403,id:10320,msg:'OWASP A03: SQLi OR/1=1 pattern',tag:'OWASP_A03',tag:'sqli'"
	
####################################################
# A04:2021 - INSECURE DESIGN
####################################################
SecRule ARGS "@contains password=" \
    "phase:2,deny,status:400,id:10500,msg:'OWASP A04: Mass assignment attempt',tag:'OWASP_A04'"

SecRule ARGS "@contains role=" \
    "phase:2,deny,status:400,id:10501,msg:'OWASP A04: Mass assignment role',tag:'OWASP_A04'"

SecRule ARGS:price|ARGS:amount "@contains -" \
    "phase:2,deny,status:400,id:10502,msg:'OWASP A04: Negative price/amount',tag:'OWASP_A04'"

SecRule REQUEST_URI "@contains /checkout/" \
    "phase:1,deny,status:403,id:10503,msg:'OWASP A04: Checkout bypass attempt',tag:'OWASP_A04'"

####################################################
# A05:2021 - SECURITY MISCONFIGURATION (ИСПРАВЛЕННЫЙ)
####################################################
SecRule REQUEST_HEADERS:User-Agent "@contains nmap" \
    "phase:1,deny,status:403,id:10600,msg:'OWASP A05: Security scanner detected',tag:'OWASP_A05'"

SecRule REQUEST_HEADERS:User-Agent "@contains sqlmap" \
    "phase:1,deny,status:403,id:10601,msg:'OWASP A05: SQL scanner detected',tag:'OWASP_A05'"

SecRule REQUEST_HEADERS:User-Agent "@contains nikto" \
    "phase:1,deny,status:403,id:10602,msg:'OWASP A05: Web scanner detected',tag:'OWASP_A05'"

SecRule REQUEST_URI "@endsWith /" \
    "phase:1,chain,id:10603,msg:'OWASP A05: Possible directory listing',tag:'OWASP_A05'"
SecRule ARGS "@rx index\.(php|asp|jsp|html)" \
    "deny,status:403"

SecRule REQUEST_FILENAME "@contains .bak" \
    "phase:1,deny,status:403,id:10604,msg:'OWASP A05: Backup file access',tag:'OWASP_A05'"

SecRule REQUEST_FILENAME "@contains .env" \
    "phase:1,deny,status:403,id:10605,msg:'OWASP A05: Config file access',tag:'OWASP_A05'"

# УПРОЩЕННЫЕ ПРАВИЛА БЕЗ CHAIN:
SecRule ARGS:username "@contains admin" \
    "phase:2,deny,status:403,id:10606,msg:'OWASP A05: Default username admin',tag:'OWASP_A05'"

SecRule ARGS:password "@contains admin" \
    "phase:2,deny,status:400,id:10607,msg:'OWASP A05: Weak password admin',tag:'OWASP_A05'"

SecRule ARGS:password "@contains 123456" \
    "phase:2,deny,status:400,id:10608,msg:'OWASP A05: Weak password 123456',tag:'OWASP_A05'"

SecRule ARGS:password "@contains password" \
    "phase:2,deny,status:400,id:10609,msg:'OWASP A05: Weak password (password)',tag:'OWASP_A05'"

####################################################
# A06:2021 - VULNERABLE AND OUTDATED COMPONENTS
####################################################
SecRule REQUEST_URI "@contains shell" \
    "phase:1,deny,status:403,id:10700,msg:'OWASP A06: Shell access attempt',tag:'OWASP_A06'"

SecRule REQUEST_URI "@contains exploit" \
    "phase:1,deny,status:403,id:10701,msg:'OWASP A06: Exploit attempt',tag:'OWASP_A06'"

SecRule REQUEST_URI "@contains /node_modules/" \
    "phase:1,deny,status:403,id:10702,msg:'OWASP A06: Component directory access',tag:'OWASP_A06'"

SecRule REQUEST_URI "@contains /vendor/" \
    "phase:1,deny,status:403,id:10703,msg:'OWASP A06: Vendor directory access',tag:'OWASP_A06'"

SecRule REQUEST_URI "@contains CVE-" \
    "phase:1,deny,status:403,id:10704,msg:'OWASP A06: CVE exploit attempt in URI',tag:'OWASP_A06'"

SecRule REQUEST_BODY "@contains CVE-" \
    "phase:2,deny,status:403,id:10705,msg:'OWASP A06: CVE exploit attempt in body',tag:'OWASP_A06'"

####################################################
# A07:2021 - IDENTIFICATION AND AUTHENTICATION FAILURES
####################################################
SecRule REQUEST_URI "@contains /rest/user/login" \
    "phase:1,pass,id:10800,msg:'OWASP A07: Login attempt',tag:'OWASP_A07'"

SecRule ARGS:password "@contains 123456" \
    "phase:2,deny,status:400,id:10802,msg:'OWASP A07: Weak password',tag:'OWASP_A07'"

SecRule ARGS:password "@contains password" \
    "phase:2,deny,status:400,id:10803,msg:'OWASP A07: Weak password',tag:'OWASP_A07'"

SecRule ARGS "@contains @gmail.com" \
    "phase:2,deny,status:400,id:10805,msg:'OWASP A07: Credential phishing',tag:'OWASP_A07'"


####################################################
# A08:2021 - SOFTWARE AND DATA INTEGRITY FAILURES
####################################################
SecRule REQUEST_BODY "@contains rO0" \
    "phase:2,deny,status:400,id:10900,msg:'OWASP A08: Deserialization attempt',tag:'OWASP_A08'"

SecRule REQUEST_BODY "@contains base64" \
    "phase:2,deny,status:400,id:10901,msg:'OWASP A08: Base64 encoded data',tag:'OWASP_A08'"

SecRule ARGS "@contains .exe" \
    "phase:2,deny,status:403,id:10902,msg:'OWASP A08: EXE file upload attempt',tag:'OWASP_A08'"

SecRule ARGS "@contains .php" \
    "phase:2,deny,status:403,id:10903,msg:'OWASP A08: PHP file upload attempt',tag:'OWASP_A08'"

SecRule ARGS:price "@contains ." \
    "phase:2,pass,id:10904,msg:'OWASP A08: Price format check',tag:'OWASP_A08'"

####################################################
# A09:2021 - SECURITY LOGGING AND MONITORING FAILURES
####################################################
SecRule REQUEST_URI "@contains /logs" \
    "phase:1,deny,status:403,id:11000,msg:'OWASP A09: Log access attempt',tag:'OWASP_A09'"

SecRule REQUEST_URI "@contains /admin" \
    "phase:1,deny,status:403,id:11001,msg:'OWASP A09: Admin access blocked',tag:'OWASP_A09'"

####################################################
# A10:2021 - SERVER-SIDE REQUEST FORGERY (SSRF)
####################################################
SecRule ARGS "@contains http://" \
    "phase:2,deny,status:403,id:11100,msg:'OWASP A10: SSRF attempt',tag:'OWASP_A10'"

SecRule ARGS "@contains https://" \
    "phase:2,deny,status:403,id:11101,msg:'OWASP A10: SSRF attempt',tag:'OWASP_A10'"

SecRule ARGS "@contains file://" \
    "phase:2,deny,status:403,id:11102,msg:'OWASP A10: SSRF file protocol',tag:'OWASP_A10'"

SecRule REQUEST_HEADERS "@contains 127.0.0.1" \
    "phase:1,deny,status:403,id:11103,msg:'OWASP A10: Localhost access',tag:'OWASP_A10'"

SecRule REQUEST_HEADERS "@contains localhost" \
    "phase:1,deny,status:403,id:11104,msg:'OWASP A10: Localhost access',tag:'OWASP_A10'"

###########################################################################
# ДОПОЛНИТЕЛЬНЫЕ ПРАВИЛА
###########################################################################
SecRule REQUEST_FILENAME|ARGS|ARGS_NAMES "@contains ../" \
    "phase:1,deny,status:403,id:12001,msg:'Path traversal detected'"

SecRule REQUEST_URI "@beginsWith /ftp" \
    "phase:1,deny,status:403,id:12002,msg:'FTP access blocked'"

SecRule REQUEST_FILENAME "@endsWith .css" \
    "phase:1,pass,id:13001,ctl:ruleEngine=Off"

SecRule REQUEST_FILENAME "@endsWith .js" \
    "phase:1,pass,id:13002,ctl:ruleEngine=Off"

SecRule REQUEST_FILENAME "@endsWith .png" \
    "phase:1,pass,id:13003,ctl:ruleEngine=Off"

SecRule REQUEST_FILENAME "@endsWith .jpg" \
    "phase:1,pass,id:13004,ctl:ruleEngine=Off"

SecRule REQUEST_FILENAME "@endsWith .jpeg" \
    "phase:1,pass,id:13005,ctl:ruleEngine=Off"

SecRule REQUEST_FILENAME "@endsWith .gif" \
    "phase:1,pass,id:13006,ctl:ruleEngine=Off"

SecRule REQUEST_FILENAME "@endsWith .ico" \
    "phase:1,pass,id:13007,ctl:ruleEngine=Off"

SecRule REQUEST_URI "@contains #" \
    "phase:1,deny,status:403,id:14001,msg:'XSS in URL fragment',tag:'xss'"

SecRule ARGS:username|ARGS:login|ARGS:user|ARGS:email "@contains <" \
    "phase:2,deny,status:400,id:15001,msg:'Special characters in login'"

SecRule ARGS:username|ARGS:login|ARGS:user|ARGS:email "@contains >" \
    "phase:2,deny,status:400,id:15002,msg:'Special characters in login'"

SecRule ARGS:username|ARGS:login|ARGS:user|ARGS:email "@contains '" \
    "phase:2,deny,status:400,id:15003,msg:'Special characters in login'"

SecRule REQUEST_BODY "@contains OR 1=1" \
    "phase:2,deny,status:400,id:15004,msg:'SQL injection in JSON',tag:'sqli'"

SecRule REQUEST_BODY "@contains union select" \
    "phase:2,deny,status:400,id:15005,msg:'SQL injection in JSON',tag:'sqli'"

SecRule REQUEST_BODY "@contains email" \
    "phase:2,pass,id:15006,msg:'Email field check'"

SecRule REQUEST_BODY "@contains username" \
    "phase:2,pass,id:15007,msg:'Username field check'"

SecRule ARGS:email|ARGS:username "@contains @" \
    "phase:2,pass,id:15008,msg:'Valid email format'"

SecRule REQUEST_BODY "@contains email" \
    "phase:2,pass,id:15009,msg:'Email length check',tag:'length'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains %3Cimg%20src" \
    "phase:1,deny,status:403,id:16001,msg:'Mixed encoded XSS'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains src%3Dx%20onerror" \
    "phase:1,deny,status:403,id:16002,msg:'Mixed encoded XSS'"

SecRule REQUEST_FILENAME "@contains /ftp" \
    "phase:1,deny,status:403,id:17001,msg:'FTP path blocked'"
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
	if r.URL.Path == "/blocked" {
        p.handleBlockedPage(w, r)
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

func (p *CorazaProxy) detectXSSInURL(r *http.Request) bool {
    // Проверяем полный URL включая фрагмент
    fullURL := r.URL.String()
    
    // Проверяем фрагмент
    if fragment := r.URL.Fragment; fragment != "" {
        // Декодируем URL-encoded символы в фрагменте
        if decoded, err := url.QueryUnescape(fragment); err == nil {
            if p.isXSSPayload(decoded) {
                return true
            }
        }
        
        // Проверяем закодированную версию
        if p.isXSSPayload(fragment) {
            return true
        }
    }
    
    // Проверяем полный URL на наличие XSS паттернов
    if p.isXSSPayload(fullURL) {
        return true
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
            fragment.includes('%3Cimg') || 
            fragment.includes('onerror=') ||
            fragment.includes('alert(') ||
            fragment.includes('<script') ||
            fragment.includes('javascript:')
        )) {
            window.location.href = '/blocked?reason=xss_fragment';
            return true;
        }
        return false;
    };
    
    // Check immediately
    if (checkFragment()) return;
    
    // Check on hash changes
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

	server := &http.Server{
		Addr:    ":" + port,
		Handler: proxy,
	}

	// Канал для сигналов завершения
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	// Запуск сервера в горутине
	go func() {
		log.Printf("Starting Coraza proxy on port %s, forwarding to %s", port, backendURL)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("Server error:", err)
		}
	}()

	// Ожидание сигнала завершения
	<-done
	log.Println("Shutting down server...")

	// Graceful shutdown с таймаутом
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatal("Server shutdown error:", err)
	}

	log.Println("Server stopped")
}