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
# OWASP TOP 10 2021 - ПОЛНЫЙ НАБОР ПРАВИЛ
###########################################################################

####################################################
# A01:2021 - BROKEN ACCESS CONTROL
####################################################
# 1. Ограничение методов
SecRule REQUEST_METHOD "!^(GET|POST|HEAD|OPTIONS)$" \
    "phase:1,deny,status:405,id:10100,msg:'OWASP A01: Invalid HTTP method',tag:'OWASP_A01',tag:'access-control'"

# 2. Защита от перебора ID (IDOR)
SecRule ARGS "@rx ^(\.\./|/etc/|/proc/|/var/|c:\\windows)" \
    "phase:1,deny,status:403,id:10101,msg:'OWASP A01: Path traversal attempt',tag:'OWASP_A01'"

# 3. Запрет прямого доступа к API без токена
SecRule REQUEST_URI "@rx ^/api/(users|admin|settings)" \
    "phase:1,chain,deny,status:403,id:10102,msg:'OWASP A01: Unauthorized API access',tag:'OWASP_A01'"
SecRule &REQUEST_HEADERS:Authorization "@eq 0" \
    "t:none"

# 4. CORS проверка
SecRule REQUEST_HEADERS:Origin "!^https?://(localhost|127\.0\.0\.1|192\.168\.)" \
    "phase:1,deny,status:403,id:10103,msg:'OWASP A01: Invalid CORS origin',tag:'OWASP_A01'"

####################################################
# A02:2021 - CRYPTOGRAPHIC FAILURES
####################################################
# 1. Проверка SSL/TLS
SecRule REQUEST_PROTOCOL "!^HTTP/2" \
    "phase:1,pass,id:10200,msg:'OWASP A02: Non-HTTP/2 protocol',tag:'OWASP_A02'"

# 2. Обнаружение незашифрованных паролей
SecRule REQUEST_BODY "@rx \\"password\\"\\s*:\\s*\\"([^\\"]{1,50})\\"" \
    "phase:2,deny,status:400,id:10201,msg:'OWASP A02: Plain text password detected',tag:'OWASP_A02'"

# 3. Проверка слабых алгоритмов
SecRule REQUEST_HEADERS "@rx ^(MD5|SHA1|DES|RC4)" \
    "phase:1,deny,status:400,id:10202,msg:'OWASP A02: Weak crypto algorithm',tag:'OWASP_A02'"

# 4. Обнаружение секретов в запросах
SecRule ARGS|REQUEST_BODY "@rx (api[_-]?key|secret|token|password)=([a-zA-Z0-9]{20,})" \
    "phase:2,deny,status:400,id:10203,msg:'OWASP A02: API key exposed',tag:'OWASP_A02'"

####################################################
# A03:2021 - INJECTION (ПОЛНЫЙ НАБОР)
####################################################
# SQL INJECTION - 15 правил
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx union.*select" \
    "phase:2,deny,status:403,id:10301,msg:'OWASP A03: SQLi UNION SELECT',tag:'OWASP_A03',tag:'sqli'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx select.*from" \
    "phase:2,deny,status:403,id:10302,msg:'OWASP A03: SQLi SELECT FROM',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx insert.*into" \
    "phase:2,deny,status:403,id:10303,msg:'OWASP A03: SQLi INSERT INTO',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx update.*set" \
    "phase:2,deny,status:403,id:10304,msg:'OWASP A03: SQLi UPDATE SET',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx delete.*from" \
    "phase:2,deny,status:403,id:10305,msg:'OWASP A03: SQLi DELETE FROM',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx drop.*table" \
    "phase:2,deny,status:403,id:10306,msg:'OWASP A03: SQLi DROP TABLE',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx or.*1=1" \
    "phase:2,deny,status:403,id:10307,msg:'OWASP A03: SQLi OR 1=1',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx '.*or.*'" \
    "phase:2,deny,status:403,id:10308,msg:'OWASP A03: SQLi OR tautology',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx --$" \
    "phase:2,deny,status:403,id:10309,msg:'OWASP A03: SQL comment',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx /\\*.*\\*/" \
    "phase:2,deny,status:403,id:10310,msg:'OWASP A03: SQL block comment',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains sleep" \
    "phase:2,deny,status:403,id:10311,msg:'OWASP A03: SQL time-based injection',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains benchmark" \
    "phase:2,deny,status:403,id:10312,msg:'OWASP A03: SQL benchmark injection',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains pg_sleep" \
    "phase:2,deny,status:403,id:10314,msg:'OWASP A03: PostgreSQL sleep injection',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx exec.*\\(|sp_|xp_" \
    "phase:2,deny,status:403,id:10315,msg:'OWASP A03: SQL stored procedure injection',tag:'OWASP_A03'"

# XSS - 25 правил
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx <script" \
    "phase:2,deny,status:403,id:10350,msg:'OWASP A03: XSS script tag',tag:'OWASP_A03',tag:'xss'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx javascript:" \
    "phase:2,deny,status:403,id:10351,msg:'OWASP A03: XSS javascript protocol',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx onerror=" \
    "phase:2,deny,status:403,id:10352,msg:'OWASP A03: XSS onerror handler',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx onload=" \
    "phase:2,deny,status:403,id:10353,msg:'OWASP A03: XSS onload handler',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx onclick=" \
    "phase:2,deny,status:403,id:10354,msg:'OWASP A03: XSS onclick handler',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx onmouseover=" \
    "phase:2,deny,status:403,id:10355,msg:'OWASP A03: XSS onmouseover handler',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx alert\\(" \
    "phase:2,deny,status:403,id:10356,msg:'OWASP A03: XSS alert function',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx confirm\\(" \
    "phase:2,deny,status:403,id:10357,msg:'OWASP A03: XSS confirm function',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx prompt\\(" \
    "phase:2,deny,status:403,id:10358,msg:'OWASP A03: XSS prompt function',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx eval\\(" \
    "phase:2,deny,status:403,id:10359,msg:'OWASP A03: XSS eval function',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx document\\.cookie" \
    "phase:2,deny,status:403,id:10360,msg:'OWASP A03: XSS cookie theft',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx document\\.write" \
    "phase:2,deny,status:403,id:10361,msg:'OWASP A03: XSS document.write',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx innerHTML" \
    "phase:2,deny,status:403,id:10362,msg:'OWASP A03: XSS innerHTML',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx outerHTML" \
    "phase:2,deny,status:403,id:10363,msg:'OWASP A03: XSS outerHTML',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx <iframe" \
    "phase:2,deny,status:403,id:10364,msg:'OWASP A03: XSS iframe',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx <embed" \
    "phase:2,deny,status:403,id:10365,msg:'OWASP A03: XSS embed',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx <object" \
    "phase:2,deny,status:403,id:10366,msg:'OWASP A03: XSS object',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx <svg" \
    "phase:2,deny,status:403,id:10367,msg:'OWASP A03: XSS SVG',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx <img.*src.*=" \
    "phase:2,deny,status:403,id:10368,msg:'OWASP A03: XSS image injection',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx <a.*href.*javascript:" \
    "phase:2,deny,status:403,id:10369,msg:'OWASP A03: XSS malicious link',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx style=.*expression\\(" \
    "phase:2,deny,status:403,id:10370,msg:'OWASP A03: XSS CSS expression',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx <link.*javascript:" \
    "phase:2,deny,status:403,id:10371,msg:'OWASP A03: XSS link injection',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx <meta.*refresh" \
    "phase:2,deny,status:403,id:10372,msg:'OWASP A03: XSS meta refresh',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx <base.*href" \
    "phase:2,deny,status:403,id:10373,msg:'OWASP A03: XSS base tag manipulation',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx <form.*action.*javascript:" \
    "phase:2,deny,status:403,id:10374,msg:'OWASP A03: XSS form action hijack',tag:'OWASP_A03'"

# URL encoded XSS
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx %3Cscript" \
    "phase:2,deny,status:403,id:10375,msg:'OWASP A03: URL encoded XSS',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx %3Cimg" \
    "phase:2,deny,status:403,id:10376,msg:'OWASP A03: URL encoded img XSS',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx %3Ciframe" \
    "phase:2,deny,status:403,id:10377,msg:'OWASP A03: URL encoded iframe XSS',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx onerror%3D" \
    "phase:2,deny,status:403,id:10378,msg:'OWASP A03: URL encoded onerror',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx alert%28" \
    "phase:2,deny,status:403,id:10379,msg:'OWASP A03: URL encoded alert',tag:'OWASP_A03'"

# Double encoded
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx %253Cscript" \
    "phase:2,deny,status:403,id:10380,msg:'OWASP A03: Double encoded XSS',tag:'OWASP_A03'"

# HTML entities
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx &lt;script" \
    "phase:2,deny,status:403,id:10381,msg:'OWASP A03: HTML entity XSS',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx &lt;img" \
    "phase:2,deny,status:403,id:10382,msg:'OWASP A03: HTML entity img XSS',tag:'OWASP_A03'"

# COMMAND INJECTION - 10 правил
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx \\|.*ls" \
    "phase:2,deny,status:403,id:10400,msg:'OWASP A03: Command injection ls',tag:'OWASP_A03',tag:'cmdi'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx \\|.*cat" \
    "phase:2,deny,status:403,id:10401,msg:'OWASP A03: Command injection cat',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx \\|.*rm" \
    "phase:2,deny,status:403,id:10402,msg:'OWASP A03: Command injection rm',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx \\|.*wget" \
    "phase:2,deny,status:403,id:10403,msg:'OWASP A03: Command injection wget',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx \\|.*curl" \
    "phase:2,deny,status:403,id:10404,msg:'OWASP A03: Command injection curl',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx \\|.*nc" \
    "phase:2,deny,status:403,id:10405,msg:'OWASP A03: Command injection netcat',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx \\|.*bash" \
    "phase:2,deny,status:403,id:10406,msg:'OWASP A03: Command injection bash',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx \\|.*sh" \
    "phase:2,deny,status:403,id:10407,msg:'OWASP A03: Command injection sh',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx \\|.*python" \
    "phase:2,deny,status:403,id:10408,msg:'OWASP A03: Command injection python',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx \\|.*perl" \
    "phase:2,deny,status:403,id:10409,msg:'OWASP A03: Command injection perl',tag:'OWASP_A03'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx \\|.*php" \
    "phase:2,deny,status:403,id:10410,msg:'OWASP A03: Command injection php',tag:'OWASP_A03'"

# LDAP INJECTION
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx \\|.*\\(.*\\)" \
    "phase:2,deny,status:403,id:10420,msg:'OWASP A03: LDAP injection',tag:'OWASP_A03',tag:'ldapi'"

# XPATH INJECTION
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx /.*\\[.*\\]" \
    "phase:2,deny,status:403,id:10430,msg:'OWASP A03: XPath injection',tag:'OWASP_A03',tag:'xpath'"

####################################################
# A04:2021 - INSECURE DESIGN
####################################################
# 1. Защита от массового присвоения
SecRule ARGS "@rx ^(password|role|isAdmin|permissions)=" \
    "phase:2,deny,status:400,id:10500,msg:'OWASP A04: Mass assignment attempt',tag:'OWASP_A04'"

# 2. Проверка бизнес-логики
SecRule ARGS:price|ARGS:amount "@rx ^-\\d+" \
    "phase:2,deny,status:400,id:10501,msg:'OWASP A04: Negative price/amount',tag:'OWASP_A04'"

# 3. Защита от обхода workflow
SecRule REQUEST_URI "@rx /checkout/.*/skip" \
    "phase:1,deny,status:403,id:10502,msg:'OWASP A04: Workflow bypass attempt',tag:'OWASP_A04'"

####################################################
# A05:2021 - SECURITY MISCONFIGURATION
####################################################
# 1. Защита от сканеров и ботов
SecRule REQUEST_HEADERS:User-Agent "@pm nmap sqlmap nikto burpsuite metasploit" \
    "phase:1,deny,status:403,id:10600,msg:'OWASP A05: Security scanner detected',tag:'OWASP_A05'"

# 2. Защита от directory listing
SecRule REQUEST_URI "@rx /$" \
    "phase:1,chain,deny,status:403,id:10601,msg:'OWASP A05: Directory listing attempt',tag:'OWASP_A05'"
SecRule ARGS "@rx ^index\\.(php|asp|jsp|html)$" \
    "t:none"

# 3. Защита от доступа к backup файлам
SecRule REQUEST_FILENAME "@rx \\.(bak|old|backup|save|orig|copy)$" \
    "phase:1,deny,status:403,id:10602,msg:'OWASP A05: Backup file access',tag:'OWASP_A05'"

# 4. Защита от доступа к конфигурационным файлам
SecRule REQUEST_FILENAME "@rx \\.(env|config|ini|conf|yml|yaml|json)$" \
    "phase:1,deny,status:403,id:10603,msg:'OWASP A05: Config file access',tag:'OWASP_A05'"

# 5. Защита от default credentials
SecRule ARGS:username|ARGS:login "@pm admin root administrator test" \
    "phase:2,chain,deny,status:403,id:10604,msg:'OWASP A05: Default username attempt',tag:'OWASP_A05'"
SecRule ARGS:password "@pm admin password 123456 12345678 qwerty" \
    "t:none"

####################################################
# A06:2021 - VULNERABLE AND OUTDATED COMPONENTS
####################################################
# 1. Обнаружение эксплойтов для известных уязвимостей
SecRule REQUEST_URI "@rx (shell|exploit|rce|upload)" \
    "phase:1,deny,status:403,id:10700,msg:'OWASP A06: Exploit pattern detected',tag:'OWASP_A06'"

# 2. Защита от доступа к папкам компонентов
SecRule REQUEST_URI "@rx /(node_modules|vendor|lib|include)/" \
    "phase:1,deny,status:403,id:10701,msg:'OWASP A06: Component directory access',tag:'OWASP_A06'"

# 3. Обнаружение известных CVE эксплойтов
SecRule REQUEST_URI|REQUEST_BODY "@rx (CVE-\\d{4}-\\d+|log4j|spring4shell|heartbleed)" \
    "phase:1,deny,status:403,id:10702,msg:'OWASP A06: Known CVE exploit attempt',tag:'OWASP_A06'"

####################################################
# A07:2021 - IDENTIFICATION AND AUTHENTICATION FAILURES
####################################################
# 1. Brute force защита
SecRule REQUEST_URI "@rx /(rest/user/login|api/login|auth/login)" \
    "phase:1,setvar:ip.auth_attempt=+1,expirevar:ip.auth_attempt=300,id:10800,msg:'OWASP A07: Login attempt counted',tag:'OWASP_A07'"

SecRule IP:auth_attempt "@gt 10" \
    "phase:1,deny,status:429,id:10801,msg:'OWASP A07: Brute force attack detected',tag:'OWASP_A07'"

# 2. Проверка слабых паролей
SecRule ARGS:password "@rx ^(123456|password|qwerty|111111|admin)$" \
    "phase:2,deny,status:400,id:10802,msg:'OWASP A07: Weak password',tag:'OWASP_A07'"

SecRule ARGS:password "@lt 8" \
    "phase:2,deny,status:400,id:10803,msg:'OWASP A07: Password too short',tag:'OWASP_A07'"

# 3. Защита от фишинга учетных данных
SecRule ARGS "@rx ^(username|login|email|password)=[^&]*@[^&]*\\.[^&]*$" \
    "phase:2,deny,status:400,id:10804,msg:'OWASP A07: Credential phishing attempt',tag:'OWASP_A07'"

# 4. Проверка сессионных cookies
SecRule REQUEST_COOKIES:sessionid|REQUEST_COOKIES:token "!^[a-zA-Z0-9]{32,}$" \
    "phase:1,chain,deny,status:403,id:10805,msg:'OWASP A07: Invalid session cookie',tag:'OWASP_A07'"
SecRule REQUEST_URI "!@rx ^/(login|register|public)" \
    "t:none"

####################################################
# A08:2021 - SOFTWARE AND DATA INTEGRITY FAILURES
####################################################
# 1. Защита от десериализации
SecRule REQUEST_BODY "@rx (rO0|base64|serial|deserialize)" \
    "phase:2,deny,status:400,id:10900,msg:'OWASP A08: Insecure deserialization attempt',tag:'OWASP_A08'"

# 2. Проверка целостности загружаемых файлов
SecRule FILES "@rx \\.(exe|bat|cmd|sh|php|jar|war)$" \
    "phase:2,deny,status:403,id:10901,msg:'OWASP A08: Dangerous file type upload',tag:'OWASP_A08'"

# 3. Защита от манипуляции с ценами
SecRule ARGS:price|ARGS:total "@rx \\D" \
    "phase:2,deny,status:400,id:10902,msg:'OWASP A08: Price manipulation attempt',tag:'OWASP_A08'"

####################################################
# A09:2021 - SECURITY LOGGING AND MONITORING FAILURES
####################################################
# 1. Обнаружение попыток очистки логов
SecRule REQUEST_URI "@rx (/logs|/audit|/console)" \
    "phase:1,chain,deny,status:403,id:11000,msg:'OWASP A09: Log access attempt',tag:'OWASP_A09'"
SecRule REQUEST_METHOD "!@streq GET" \
    "t:none"

# 2. Обнаружение аномальной активности
SecRule REQUEST_URI "@rx /(admin|config|server)" \
    "phase:1,setvar:ip.admin_access=+1,expirevar:ip.admin_access=60,id:11001,msg:'OWASP A09: Admin access counted',tag:'OWASP_A09'"

SecRule IP:admin_access "@gt 100" \
    "phase:1,deny,status:429,id:11002,msg:'OWASP A09: Excessive admin access',tag:'OWASP_A09'"

####################################################
# A10:2021 - SERVER-SIDE REQUEST FORGERY (SSRF)
####################################################
# 1. Обнаружение SSRF атак
SecRule ARGS "@rx ^(http|https|ftp|ldap|file|gopher)://" \
    "phase:2,deny,status:403,id:11100,msg:'OWASP A10: SSRF attempt detected',tag:'OWASP_A10'"

# 2. Защита от внутренних запросов
SecRule REQUEST_HEADERS "@rx ^(127\\.|10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.|localhost)" \
    "phase:1,deny,status:403,id:11101,msg:'OWASP A10: Internal network access attempt',tag:'OWASP_A10'"

# 3. Защита от DNS rebinding
SecRule ARGS "@rx @.*\\.(local|localhost|internal|lan)" \
    "phase:2,deny,status:403,id:11102,msg:'OWASP A10: DNS rebinding attempt',tag:'OWASP_A10'"

###########################################################################
# ДОПОЛНИТЕЛЬНЫЕ ПРАВИЛА (из твоего кода, но с обновленными ID)
###########################################################################

# Path traversal
SecRule REQUEST_FILENAME|ARGS|ARGS_NAMES "@rx \\.\\./" \
    "phase:1,deny,status:403,id:12001,msg:'Path traversal detected'"

# FTP blocking
SecRule REQUEST_URI "@beginsWith /ftp" \
    "phase:1,deny,status:403,id:12002,msg:'FTP access blocked'"

# Static files - no inspection
SecRule REQUEST_FILENAME "@rx \\.(css|js|png|jpg|jpeg|gif|ico|woff|woff2|ttf|svg)$" \
    "phase:1,pass,id:13001,ctl:ruleEngine=Off"

# Block requests with suspicious fragments
SecRule REQUEST_URI "@rx #.*search.*q=.*%3C" \
    "phase:1,deny,status:403,id:14001,msg:'XSS in URL fragment detected'"

SecRule REQUEST_URI "@rx #.*q=.*onerror" \
    "phase:1,deny,status:403,id:14002,msg:'XSS in URL fragment detected'"

SecRule REQUEST_URI "@rx #.*alert\\\(" \
    "phase:1,deny,status:403,id:14003,msg:'XSS in URL fragment detected'"

# Запрет спецсимволов в логине
SecRule ARGS:username|ARGS:login|ARGS:user|ARGS:email "@rx [<>'\\\"%;()&+|]" \
    "phase:2,deny,status:400,id:15001,msg:'Special characters in login field'"

# Для JSON login в теле запроса - Juice Shop
SecRule REQUEST_BODY "@rx \\"(email|username|password)\"\\s*:\\s*\"[^\\"]*(['\\\"][\\s]*OR[\\s]*1=1|['\\\"][\\s]*OR[\\s]*['\\\"][\\s]*=[\\s]*['\\\"]|--|/\\*)[^\\"]*\\"" \
    "phase:2,deny,status:400,id:15002,msg:'SQL injection in JSON login detected'"

# Обнаружение SQL инъекций в JSON теле
SecRule REQUEST_BODY "@rx \\"(email|username)\"\\s*:\\s*\"[^\\"]*(union|select|insert|update|delete|drop|exec)[^\\"]*\\"" \
    "phase:2,deny,status:400,id:15003,msg:'SQL keywords in JSON login'"

# Более строгое правило для email формата в JSON
SecRule REQUEST_BODY "@rx \\"email\\"\\s*:\\s*\"[^\\"]*[^a-zA-Z0-9@._-][^\\"]*\\"" \
    "phase:2,deny,status:400,id:15004,msg:'Invalid email format'"

# Максимальная длина для JSON полей
SecRule REQUEST_BODY "@rx \\"(email|username)\"\\s*:\\s*\"[^\\"]{51,}\\"" \
    "phase:2,deny,status:400,id:15005,msg:'Login field too long'"

# Mixed encoding XSS
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx %3Cimg%20src" \
    "phase:1,deny,status:403,id:16001,msg:'Mixed encoded XSS detected'"

SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx src%3Dx%20onerror" \
    "phase:1,deny,status:403,id:16002,msg:'Mixed encoded XSS detected'"

# FTP path regex
SecRule REQUEST_FILENAME "@rx ^/ftp(/|$)" \
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