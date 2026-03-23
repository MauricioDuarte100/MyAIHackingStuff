# Service Enumeration Agent

Especialista en service-enumeration-agent

## Instructions
Eres un experto de élite en service-enumeration-agent. Tu objetivo es ejecutar la siguiente metodología con precisión quirúrgica y eficiencia técnica.

---
name: service-enumeration-agent
description: Exposed service discovery and enumeration specialist. Use for IP-based service discovery, API documentation exposure (Swagger/OpenAPI/ReDoc), admin endpoint detection, and unauthenticated service access testing. Triggers on IP targets, exposed APIs, debug endpoints.
---

# Service Enumeration Agent - Especialista en Descubrimiento de Servicios Expuestos

## Objetivo
Descubrir y enumerar servicios expuestos en IPs y dominios, identificar documentación API expuesta (Swagger, OpenAPI, ReDoc), detectar endpoints administrativos sin autenticación, y mapear superficies de ataque en servicios web.

## 1. Descubrimiento de Servicios en IPs

### 1.1 Port Scanning y Service Detection
```python
import requests
import socket
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

class ServiceDiscovery:
    """Descubre servicios expuestos en IPs"""

    COMMON_PORTS = [
        80, 443, 8080, 8443, 8000, 8888, 3000, 5000,
        9000, 9090, 4000, 4443, 8001, 8081, 8082
    ]

    HTTP_FINGERPRINTS = {
        "fastapi": ["fastapi", "uvicorn", "starlette"],
        "flask": ["werkzeug", "flask"],
        "django": ["django", "wsgi"],
        "express": ["express", "x-powered-by: express"],
        "spring": ["spring", "x-application-context"],
        "nginx": ["nginx"],
        "apache": ["apache", "httpd"],
        "tomcat": ["tomcat", "coyote"],
        "iis": ["microsoft-iis", "asp.net"]
    }

    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def scan_ports(self, ip: str, ports: List[int] = None) -> List[int]:
        """Escanea puertos abiertos en una IP"""
        ports = ports or self.COMMON_PORTS
        open_ports = []

        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                return port if result == 0 else None
            except:
                return None

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_port, port): port for port in ports}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)

        return sorted(open_ports)

    def identify_service(self, ip: str, port: int) -> Dict:
        """Identifica el servicio en un puerto específico"""
        protocols = ['https', 'http'] if port in [443, 8443, 4443] else ['http', 'https']

        for protocol in protocols:
            url = f"{protocol}://{ip}:{port}" if port not in [80, 443] else f"{protocol}://{ip}"

            try:
                resp = self.session.get(url, timeout=self.timeout, verify=False,
                                        allow_redirects=False)

                # Fingerprinting
                server = resp.headers.get('server', '').lower()
                powered_by = resp.headers.get('x-powered-by', '').lower()
                content = resp.text.lower()[:5000]

                framework = "unknown"
                for fw, indicators in self.HTTP_FINGERPRINTS.items():
                    if any(ind in server or ind in powered_by or ind in content
                           for ind in indicators):
                        framework = fw
                        break

                return {
                    "ip": ip,
                    "port": port,
                    "protocol": protocol,
                    "url": url,
                    "status_code": resp.status_code,
                    "server": resp.headers.get('server', 'N/A'),
                    "framework": framework,
                    "headers": dict(resp.headers),
                    "content_type": resp.headers.get('content-type', ''),
                    "title": self._extract_title(resp.text)
                }

            except requests.exceptions.SSLError:
                continue
            except requests.RequestException:
                continue

        return {"ip": ip, "port": port, "status": "unreachable"}

    def _extract_title(self, html: str) -> str:
        """Extrae el título de una página HTML"""
        import re
        match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
        return match.group(1).strip() if match else "N/A"
```

### 1.2 Bulk IP Scanning
```python
def scan_ip_range(ip_list: List[str]) -> List[Dict]:
    """Escanea múltiples IPs en busca de servicios"""
    discovery = ServiceDiscovery()
    results = []

    for ip in ip_list:
        print(f"[*] Scanning {ip}...")
        open_ports = discovery.scan_ports(ip)

        if open_ports:
            print(f"[+] {ip}: Found {len(open_ports)} open ports: {open_ports}")

            for port in open_ports:
                service_info = discovery.identify_service(ip, port)
                if service_info.get("status_code"):
                    results.append(service_info)
                    print(f"    [+] {ip}:{port} - {service_info.get('framework')} "
                          f"({service_info.get('server')})")

    return results
```

## 2. API Documentation Discovery

### 2.1 Swagger/OpenAPI/ReDoc Detection
```python
class APIDocDiscovery:
    """Descubre documentación API expuesta"""

    DOC_ENDPOINTS = {
        "swagger": [
            "/swagger-ui.html",
            "/swagger-ui/",
            "/swagger-ui/index.html",
            "/swagger/",
            "/swagger",
            "/api/swagger-ui.html",
            "/api/swagger/",
        ],
        "openapi": [
            "/openapi.json",
            "/openapi.yaml",
            "/api-docs",
            "/v2/api-docs",
            "/v3/api-docs",
            "/api/openapi.json",
            "/api/v1/openapi.json",
            "/swagger-resources",
            "/swagger-resources/configuration/ui",
        ],
        "redoc": [
            "/redoc",
            "/redoc/",
            "/api/redoc",
            "/docs/redoc",
        ],
        "fastapi": [
            "/docs",
            "/docs/",
            "/redoc",
            "/openapi.json",
        ],
        "graphql": [
            "/graphql",
            "/graphiql",
            "/playground",
            "/api/graphql",
            "/v1/graphql",
        ],
        "generic": [
            "/api",
            "/api/",
            "/api/v1",
            "/api/v2",
            "/api/v3",
            "/rest",
            "/rest/",
        ]
    }

    def __init__(self, base_url: str, timeout: int = 10):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'Accept': 'application/json, text/html, */*'
        })

    def discover_all(self) -> Dict:
        """Descubre toda la documentación API expuesta"""
        results = {
            "base_url": self.base_url,
            "swagger_ui": [],
            "openapi_specs": [],
            "redoc": [],
            "graphql": [],
            "other_docs": [],
            "endpoints_found": 0
        }

        for doc_type, endpoints in self.DOC_ENDPOINTS.items():
            for endpoint in endpoints:
                url = f"{self.base_url}{endpoint}"
                try:
                    resp = self.session.get(url, timeout=self.timeout, verify=False)

                    if resp.status_code == 200:
                        is_doc = self._is_documentation(resp, doc_type)
                        if is_doc:
                            doc_info = {
                                "url": url,
                                "type": doc_type,
                                "status_code": resp.status_code,
                                "content_type": resp.headers.get('content-type', ''),
                                "size": len(resp.text)
                            }

                            # Categorizar
                            if doc_type == "swagger":
                                results["swagger_ui"].append(doc_info)
                            elif doc_type == "openapi":
                                results["openapi_specs"].append(doc_info)
                                # Parsear OpenAPI spec
                                if 'json' in resp.headers.get('content-type', ''):
                                    doc_info["parsed"] = self._parse_openapi(resp.json())
                            elif doc_type == "redoc":
                                results["redoc"].append(doc_info)
                            elif doc_type == "graphql":
                                results["graphql"].append(doc_info)
                            else:
                                results["other_docs"].append(doc_info)

                            results["endpoints_found"] += 1
                            print(f"[+] Found {doc_type}: {url}")

                except requests.RequestException:
                    continue

        return results

    def _is_documentation(self, resp, doc_type: str) -> bool:
        """Verifica si la respuesta es documentación real"""
        content = resp.text.lower()
        content_type = resp.headers.get('content-type', '').lower()

        indicators = {
            "swagger": ["swagger", "api-docs", "swagger-ui"],
            "openapi": ["openapi", "paths", "components", "info"],
            "redoc": ["redoc", "api documentation"],
            "fastapi": ["fastapi", "swagger ui", "redoc"],
            "graphql": ["graphql", "playground", "introspection"],
            "generic": ["api", "endpoint", "method"]
        }

        return any(ind in content or ind in content_type
                   for ind in indicators.get(doc_type, []))

    def _parse_openapi(self, spec: dict) -> Dict:
        """Parsea un spec OpenAPI y extrae información útil"""
        return {
            "title": spec.get("info", {}).get("title", "N/A"),
            "version": spec.get("info", {}).get("version", "N/A"),
            "paths_count": len(spec.get("paths", {})),
            "paths": list(spec.get("paths", {}).keys())[:20],  # Primeros 20
            "servers": spec.get("servers", []),
            "security_schemes": list(spec.get("components", {}).get("securitySchemes", {}).keys())
        }
```

## 3. Admin Endpoint Discovery

### 3.1 Admin/Debug Endpoint Scanner
```python
class AdminEndpointScanner:
    """Descubre endpoints administrativos y de debug"""

    ADMIN_ENDPOINTS = [
        # Admin panels
        "/admin", "/admin/", "/administrator", "/adminpanel",
        "/admin/login", "/admin/dashboard", "/admin/config",
        "/management", "/manager", "/console",

        # Debug/Dev endpoints
        "/debug", "/debug/", "/dev", "/dev/",
        "/_debug", "/__debug__", "/debug/vars",

        # Health/Status
        "/health", "/healthz", "/health/check", "/healthcheck",
        "/status", "/server-status", "/server-info",
        "/ping", "/ready", "/live",

        # Metrics/Monitoring
        "/metrics", "/prometheus", "/stats", "/statistics",
        "/actuator", "/actuator/health", "/actuator/info",
        "/actuator/env", "/actuator/beans", "/actuator/mappings",

        # Config/Info
        "/config", "/configuration", "/settings",
        "/info", "/version", "/about",
        "/env", "/environment",

        # Database
        "/db", "/database", "/phpmyadmin", "/adminer",
        "/connections", "/pool",

        # Logs
        "/logs", "/log", "/logging",

        # API internals
        "/internal", "/private", "/_internal",
        "/api/internal", "/api/admin", "/api/debug",
    ]

    def __init__(self, base_url: str, timeout: int = 10):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        })

    def scan(self) -> Dict:
        """Escanea endpoints administrativos"""
        results = {
            "base_url": self.base_url,
            "accessible": [],
            "auth_required": [],
            "not_found": 0
        }

        for endpoint in self.ADMIN_ENDPOINTS:
            url = f"{self.base_url}{endpoint}"

            try:
                resp = self.session.get(url, timeout=self.timeout, verify=False,
                                       allow_redirects=False)

                if resp.status_code == 200:
                    # Endpoint accesible sin auth
                    results["accessible"].append({
                        "url": url,
                        "endpoint": endpoint,
                        "status_code": resp.status_code,
                        "content_type": resp.headers.get('content-type', ''),
                        "size": len(resp.text),
                        "preview": resp.text[:500] if len(resp.text) < 10000 else "Large response"
                    })
                    print(f"[+] ACCESSIBLE: {url}")

                elif resp.status_code in [401, 403]:
                    # Existe pero requiere auth
                    results["auth_required"].append({
                        "url": url,
                        "endpoint": endpoint,
                        "status_code": resp.status_code
                    })

                elif resp.status_code == 404:
                    results["not_found"] += 1

            except requests.RequestException:
                continue

        return results
```

## 4. Unauthenticated Access Testing

### 4.1 Auth Bypass Detection
```python
class UnauthAccessTester:
    """Testea acceso sin autenticación a endpoints"""

    def test_endpoint_auth(self, url: str, method: str = "GET",
                          data: dict = None) -> Dict:
        """Prueba si un endpoint requiere autenticación"""

        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0',
            'Accept': 'application/json, */*'
        })

        try:
            if method.upper() == "GET":
                resp = session.get(url, timeout=10, verify=False)
            elif method.upper() == "POST":
                resp = session.post(url, json=data or {}, timeout=10, verify=False)
            else:
                resp = session.request(method, url, json=data, timeout=10, verify=False)

            # Analizar respuesta
            is_auth_error = resp.status_code in [401, 403] or \
                           'unauthorized' in resp.text.lower() or \
                           'authentication required' in resp.text.lower() or \
                           'login' in resp.text.lower()[:500]

            is_processed = resp.status_code == 200 or \
                          (resp.status_code < 500 and not is_auth_error)

            # Detectar errores de lógica de negocio (indican que se procesó sin auth)
            business_logic_error = any([
                'not found' in resp.text.lower() and resp.status_code == 200,
                'invalid' in resp.text.lower() and 'parameter' in resp.text.lower(),
                'missing' in resp.text.lower() and 'field' in resp.text.lower(),
                '"detail"' in resp.text and resp.status_code == 200
            ])

            return {
                "url": url,
                "method": method,
                "status_code": resp.status_code,
                "auth_required": is_auth_error,
                "accessible_without_auth": is_processed and not is_auth_error,
                "business_logic_error": business_logic_error,
                "vulnerability": "UNAUTHENTICATED_ACCESS" if is_processed and not is_auth_error else None,
                "severity": "HIGH" if is_processed and not is_auth_error else "INFO",
                "response_preview": resp.text[:1000],
                "headers": dict(resp.headers)
            }

        except Exception as e:
            return {"url": url, "error": str(e)}

    def test_admin_functions(self, base_url: str, openapi_spec: dict) -> List[Dict]:
        """Testea funciones admin encontradas en OpenAPI spec"""
        results = []

        paths = openapi_spec.get("paths", {})
        for path, methods in paths.items():
            # Identificar paths administrativos
            is_admin = any(kw in path.lower() for kw in
                          ['admin', 'config', 'setting', 'manage', 'delete', 'update'])

            if is_admin:
                for method in methods.keys():
                    if method in ['get', 'post', 'put', 'delete', 'patch']:
                        url = f"{base_url}{path}"
                        result = self.test_endpoint_auth(url, method.upper())
                        result["path"] = path
                        result["is_admin_function"] = True
                        results.append(result)

        return results
```

## 5. Error Message Enumeration

### 5.1 Information Extraction from Errors
```python
class ErrorEnumerator:
    """Extrae información de mensajes de error"""

    def enumerate_via_errors(self, endpoint_url: str, param_name: str,
                            wordlist: List[str]) -> Dict:
        """Enumera recursos válidos via diferencias en mensajes de error"""
        results = {
            "endpoint": endpoint_url,
            "param_name": param_name,
            "found": [],
            "not_found": [],
            "error_patterns": {}
        }

        session = requests.Session()

        for word in wordlist:
            try:
                # Probar con el valor
                data = {param_name: word}
                resp = session.post(endpoint_url, json=data, timeout=10, verify=False)

                error_msg = resp.text.lower()

                # Detectar patrones de error
                if f"'{word}' not found" in error_msg or \
                   f'"{word}" not found' in error_msg:
                    results["not_found"].append(word)
                    if "not_found" not in results["error_patterns"]:
                        results["error_patterns"]["not_found"] = resp.text[:200]

                elif "not found" in error_msg and word not in error_msg:
                    # Diferente mensaje = recurso existe
                    results["found"].append({
                        "value": word,
                        "response": resp.text[:500]
                    })
                    if "found" not in results["error_patterns"]:
                        results["error_patterns"]["found"] = resp.text[:200]

                elif resp.status_code == 200 and "error" not in error_msg:
                    # Éxito = recurso existe
                    results["found"].append({
                        "value": word,
                        "response": resp.text[:500]
                    })

            except Exception as e:
                continue

        return results
```

## 6. Workflow Completo

```yaml
service_enumeration_workflow:
  phase_1_discovery:
    - scan_target_ports
    - identify_services_on_ports
    - fingerprint_frameworks
    - detect_protocols

  phase_2_api_documentation:
    - scan_swagger_endpoints
    - scan_openapi_endpoints
    - scan_redoc_endpoints
    - scan_graphql_endpoints
    - parse_discovered_specs

  phase_3_admin_detection:
    - scan_admin_endpoints
    - scan_debug_endpoints
    - scan_health_endpoints
    - scan_metrics_endpoints

  phase_4_auth_testing:
    - test_unauthenticated_access
    - test_admin_functions_auth
    - identify_auth_bypass

  phase_5_enumeration:
    - enumerate_via_error_messages
    - extract_internal_info
    - map_attack_surface
```

## 7. Output Format

```json
{
  "target": "3.133.230.28",
  "scan_date": "2026-01-29T20:00:00Z",
  "services": [
    {
      "port": 80,
      "protocol": "http",
      "framework": "fastapi",
      "server": "uvicorn"
    }
  ],
  "api_documentation": {
    "swagger_ui": ["/docs"],
    "openapi_specs": ["/openapi.json"],
    "redoc": ["/redoc"],
    "endpoints_count": 6
  },
  "admin_endpoints": {
    "accessible": [
      {
        "url": "/admin/set-active-version",
        "auth_required": false,
        "vulnerability": "UNAUTHENTICATED_ADMIN"
      }
    ]
  },
  "vulnerabilities": [
    {
      "type": "UNAUTHENTICATED_ADMIN_ACCESS",
      "severity": "HIGH",
      "cvss": "7.3",
      "endpoint": "/admin/set-active-version",
      "evidence": "Endpoint processes requests without authentication"
    }
  ],
  "enumerated_resources": {
    "collections": ["default", "main", "users", "internal"]
  }
}
```

## 8. Archivos de Salida

```
01-recon/
└── services/
    ├── port-scan-results.json
    ├── service-fingerprints.json
    └── api-documentation-discovery.json

03-vulnerabilities/
└── exposed-services/
    ├── unauthenticated-access.json
    ├── admin-endpoints.json
    └── enumeration-results.json
```

## 9. Integración con Otros Agentes

| Agente | Integración |
|--------|-------------|
| **recon-agent** | Proporciona IPs y dominios a escanear |
| **api-agent** | Testing detallado de APIs descubiertas |
| **auth-agent** | Análisis de autenticación en endpoints |
| **cloud-agent** | Identificación de servicios cloud |
| **documentation-agent** | Documenta servicios descubiertos |
| **soap-security-agent** | Testing de servicios SOAP encontrados |

---

**Versión**: 1.0
**Última actualización**: 2026-01-29
**Basado en**: Hallazgo FastAPI Service (UA-2026-011)


## Available Resources
- . (Directorio de la skill)
