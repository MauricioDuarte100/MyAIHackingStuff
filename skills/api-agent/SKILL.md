---
name: api-agent
description: Agente especializado en testing de APIs REST, GraphQL y WebSocket. Usar para: (1) Descubrimiento de endpoints, (2) Análisis de schemas GraphQL, (3) Testing de autenticación/autorización en APIs, (4) Fuzzing de parámetros, (5) Detección de IDOR, (6) Rate limiting bypass, (7) Análisis de WebSockets. Trigger: cuando se identifiquen APIs que necesiten testing de seguridad.
---

# 🔌 API Agent - Agente de Testing de APIs

## Objetivo
Realizar testing exhaustivo de APIs REST, GraphQL y WebSocket para identificar vulnerabilidades.

## 1. REST API Testing

### Endpoint Discovery
```python
import requests
from urllib.parse import urljoin
import json

class RESTDiscovery:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Security Research)"
        })
        
    def discover_api_versions(self):
        """Buscar diferentes versiones de API"""
        versions = [
            "/api", "/api/v1", "/api/v2", "/api/v3",
            "/v1", "/v2", "/v3",
            "/api/latest", "/api/beta",
            "/rest", "/rest/v1",
            "/graphql", "/graphql/v1",
            "/_api", "/internal/api"
        ]
        
        found = []
        for ver in versions:
            url = urljoin(self.base_url, ver)
            try:
                r = self.session.get(url, timeout=5)
                if r.status_code not in [404, 403]:
                    found.append({
                        "path": ver,
                        "status": r.status_code,
                        "content_type": r.headers.get("Content-Type"),
                        "response_size": len(r.content)
                    })
            except:
                pass
        
        return found
    
    def fuzz_endpoints(self, base_path, wordlist):
        """Fuzzing de endpoints"""
        found = []
        
        for word in wordlist:
            url = urljoin(self.base_url, f"{base_path}/{word}")
            try:
                r = self.session.get(url, timeout=5)
                if r.status_code not in [404]:
                    found.append({
                        "path": f"{base_path}/{word}",
                        "status": r.status_code,
                        "methods": self.check_methods(url)
                    })
            except:
                pass
        
        return found
    
    def check_methods(self, url):
        """Verificar métodos HTTP permitidos"""
        methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
        allowed = []
        
        # OPTIONS primero
        try:
            r = self.session.options(url)
            if "Allow" in r.headers:
                return r.headers["Allow"].split(", ")
        except:
            pass
        
        # Probar cada método
        for method in methods:
            try:
                r = self.session.request(method, url, timeout=5)
                if r.status_code not in [404, 405]:
                    allowed.append(method)
            except:
                pass
        
        return allowed
```

### Parameter Discovery
```python
def discover_parameters(url, method="GET"):
    """Descubrir parámetros ocultos"""
    
    common_params = [
        # Paginación
        "page", "limit", "offset", "size", "per_page", "skip", "take",
        # Filtrado
        "filter", "query", "q", "search", "sort", "order", "orderby",
        # IDs
        "id", "user_id", "userId", "uid", "account_id",
        # Formato
        "format", "type", "output", "callback", "jsonp",
        # Debug
        "debug", "test", "dev", "verbose", "trace",
        # Auth
        "token", "api_key", "apikey", "key", "access_token",
        # Expansión
        "include", "expand", "fields", "select", "populate",
        # Versioning
        "version", "v", "api_version"
    ]
    
    discovered = []
    
    for param in common_params:
        # Probar con diferentes valores
        test_values = ["1", "true", "admin", "test", "*"]
        
        for value in test_values:
            params = {param: value}
            try:
                r = requests.get(url, params=params, timeout=5)
                
                # Comparar con request base
                base_r = requests.get(url, timeout=5)
                
                if (r.status_code != base_r.status_code or 
                    len(r.content) != len(base_r.content)):
                    discovered.append({
                        "param": param,
                        "value": value,
                        "effect": "Response changed",
                        "base_status": base_r.status_code,
                        "new_status": r.status_code
                    })
                    break
            except:
                pass
    
    return discovered
```

### IDOR Testing
```python
class IDORTester:
    def __init__(self, session):
        self.session = session
        
    def test_idor(self, url_template, id_param, user_ids):
        """
        Test IDOR en endpoints
        url_template: "/api/users/{id}/profile"
        id_param: "id"
        user_ids: [1, 2, 3, "admin", "00000000-0000-0000-0000-000000000001"]
        """
        results = []
        
        for uid in user_ids:
            url = url_template.replace(f"{{{id_param}}}", str(uid))
            
            try:
                r = self.session.get(url, timeout=5)
                
                if r.status_code == 200:
                    results.append({
                        "id": uid,
                        "accessible": True,
                        "data_preview": r.text[:200],
                        "potential_idor": True
                    })
                else:
                    results.append({
                        "id": uid,
                        "accessible": False,
                        "status": r.status_code
                    })
            except Exception as e:
                results.append({
                    "id": uid,
                    "error": str(e)
                })
        
        return results
    
    def generate_test_ids(self, base_id):
        """Generar IDs de prueba basados en el ID del usuario"""
        test_ids = []
        
        if isinstance(base_id, int):
            # Sequential IDs
            test_ids.extend([base_id - 1, base_id + 1, 1, 0, -1])
        
        if isinstance(base_id, str):
            # UUID manipulation
            if len(base_id) == 36:  # UUID format
                test_ids.append(base_id[:-1] + "0")
                test_ids.append("00000000-0000-0000-0000-000000000000")
                test_ids.append("00000000-0000-0000-0000-000000000001")
        
        return test_ids
```

## 2. GraphQL Testing

### Schema Analysis
```python
class GraphQLAnalyzer:
    def __init__(self, endpoint):
        self.endpoint = endpoint
        self.schema = None
        
    def introspect(self):
        """Obtener schema completo via introspección"""
        introspection_query = """
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
              kind
              name
              description
              fields(includeDeprecated: true) {
                name
                description
                args {
                  name
                  description
                  type {
                    kind
                    name
                    ofType {
                      kind
                      name
                    }
                  }
                  defaultValue
                }
                type {
                  kind
                  name
                  ofType {
                    kind
                    name
                  }
                }
                isDeprecated
                deprecationReason
              }
              inputFields {
                name
                type {
                  kind
                  name
                }
              }
              interfaces {
                name
              }
              enumValues(includeDeprecated: true) {
                name
                isDeprecated
              }
              possibleTypes {
                name
              }
            }
            directives {
              name
              description
              locations
              args {
                name
                type {
                  kind
                  name
                }
              }
            }
          }
        }
        """
        
        r = requests.post(self.endpoint, 
                         json={"query": introspection_query})
        
        if r.status_code == 200:
            self.schema = r.json()
            return self.schema
        else:
            return {"error": "Introspection disabled or failed"}
    
    def find_sensitive_fields(self):
        """Buscar campos sensibles en el schema"""
        sensitive_patterns = [
            "password", "secret", "token", "key", "apikey",
            "credit", "card", "ssn", "social",
            "private", "internal", "admin", "debug",
            "email", "phone", "address"
        ]
        
        sensitive_fields = []
        
        if not self.schema:
            self.introspect()
        
        for type_info in self.schema.get("data", {}).get("__schema", {}).get("types", []):
            type_name = type_info.get("name", "")
            fields = type_info.get("fields", []) or []
            
            for field in fields:
                field_name = field.get("name", "").lower()
                
                for pattern in sensitive_patterns:
                    if pattern in field_name:
                        sensitive_fields.append({
                            "type": type_name,
                            "field": field.get("name"),
                            "pattern_matched": pattern
                        })
        
        return sensitive_fields
    
    def generate_queries(self):
        """Generar queries automáticas para cada tipo"""
        queries = []
        
        if not self.schema:
            self.introspect()
        
        query_type = self.schema.get("data", {}).get("__schema", {}).get("queryType", {})
        
        # Buscar el tipo Query en types
        for type_info in self.schema.get("data", {}).get("__schema", {}).get("types", []):
            if type_info.get("name") == query_type.get("name"):
                for field in type_info.get("fields", []):
                    query = self._build_query(field)
                    queries.append(query)
        
        return queries
    
    def _build_query(self, field, depth=3):
        """Construir query recursivamente"""
        if depth == 0:
            return field.get("name")
        
        # Simplificado - en producción sería más complejo
        return f"query {{ {field.get('name')} {{ id }} }}"
```

### GraphQL Vulnerabilities
```python
graphql_tests = {
    "batching_attack": lambda n: [
        {"query": f"query {{ user(id: {i}) {{ email password }} }}"}
        for i in range(1, n+1)
    ],
    
    "alias_dos": lambda n: "query { " + " ".join([
        f"a{i}: __typename" for i in range(n)
    ]) + " }",
    
    "nested_query_dos": """
        query {
            user(id: 1) {
                friends {
                    friends {
                        friends {
                            friends {
                                id
                            }
                        }
                    }
                }
            }
        }
    """,
    
    "field_suggestions": """
        query { user { NONEXISTENT_FIELD_12345 } }
    """,
    
    "directive_overloading": """
        query {
            user @skip(if: false) @skip(if: false) @skip(if: false) {
                id
            }
        }
    """
}
```

## 3. WebSocket Testing

### WebSocket Analyzer
```python
import asyncio
import websockets
import json

class WebSocketTester:
    def __init__(self, ws_url):
        self.ws_url = ws_url
        self.messages = []
        
    async def connect_and_listen(self, duration=30):
        """Conectar y escuchar mensajes"""
        async with websockets.connect(self.ws_url) as ws:
            start = asyncio.get_event_loop().time()
            
            while asyncio.get_event_loop().time() - start < duration:
                try:
                    msg = await asyncio.wait_for(ws.recv(), timeout=5)
                    self.messages.append({
                        "timestamp": asyncio.get_event_loop().time(),
                        "direction": "received",
                        "data": msg
                    })
                except asyncio.TimeoutError:
                    pass
        
        return self.messages
    
    async def test_injection(self, payloads):
        """Enviar payloads de prueba"""
        results = []
        
        async with websockets.connect(self.ws_url) as ws:
            for payload in payloads:
                await ws.send(payload)
                
                try:
                    response = await asyncio.wait_for(ws.recv(), timeout=5)
                    results.append({
                        "payload": payload,
                        "response": response,
                        "error": False
                    })
                except asyncio.TimeoutError:
                    results.append({
                        "payload": payload,
                        "response": None,
                        "error": "Timeout"
                    })
                except Exception as e:
                    results.append({
                        "payload": payload,
                        "response": None,
                        "error": str(e)
                    })
        
        return results

# Payloads para WebSocket
ws_payloads = [
    # JSON Injection
    '{"type":"message","data":"test"}',
    '{"type":"message","data":"<script>alert(1)</script>"}',
    '{"type":"admin","action":"getUsers"}',
    '{"type":"subscribe","channel":"../../../etc/passwd"}',
    
    # CSWSH (Cross-Site WebSocket Hijacking)
    # Verificar Origin header
]
```

## 4. Authentication Testing

### JWT Analysis
```python
import base64
import json

def analyze_jwt(token):
    """Analizar token JWT"""
    parts = token.split('.')
    
    if len(parts) != 3:
        return {"error": "Invalid JWT format"}
    
    # Decodificar header y payload
    header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
    
    vulnerabilities = []
    
    # Verificar algoritmo
    if header.get('alg') == 'none':
        vulnerabilities.append("CRITICAL: Algorithm 'none' - Token can be forged")
    
    if header.get('alg') in ['HS256', 'HS384', 'HS512']:
        vulnerabilities.append("INFO: Symmetric algorithm - Try key bruteforce")
    
    # Verificar claims
    if 'exp' not in payload:
        vulnerabilities.append("MEDIUM: No expiration claim")
    
    if 'admin' in payload or 'role' in payload:
        vulnerabilities.append("INFO: Role claim present - Test privilege escalation")
    
    return {
        "header": header,
        "payload": payload,
        "signature": parts[2][:20] + "...",
        "vulnerabilities": vulnerabilities
    }

# Ataques JWT
jwt_attacks = {
    "none_algorithm": lambda payload: f"{base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).decode().rstrip('=')}.{base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')}.",
    
    "key_confusion": "# Cambiar RS256 a HS256 y firmar con clave pública",
    
    "weak_secret": [
        "secret", "password", "123456", "jwt_secret",
        "your-256-bit-secret", "key", "private"
    ]
}
```

## Workflow de API Testing

```
1. DESCUBRIMIENTO
   ├── Identificar endpoints de API
   ├── Detectar versiones (v1, v2, etc.)
   ├── Encontrar documentación (swagger, openapi)
   └── Mapear GraphQL schema

2. AUTENTICACIÓN
   ├── Analizar mecanismo (JWT, OAuth, API Key)
   ├── Probar bypasses
   ├── Verificar gestión de sesiones
   └── Test de tokens

3. AUTORIZACIÓN
   ├── IDOR testing
   ├── Horizontal privilege escalation
   ├── Vertical privilege escalation
   └── Function-level access control

4. INPUT VALIDATION
   ├── Parameter fuzzing
   ├── Mass assignment
   ├── Injection testing
   └── File upload testing

5. RATE LIMITING
   ├── Verificar límites
   ├── Bypass techniques
   └── Resource exhaustion
```

## Archivos de Salida

- `02-mapping/api-specs/rest/endpoints.json`
- `02-mapping/api-specs/graphql/schema.json`
- `05-api-testing/graphql/introspection.json`
- `05-api-testing/graphql/vulnerabilities/`
- `05-api-testing/rest/vulnerabilities/`
- `06-evidence/requests/api/`
