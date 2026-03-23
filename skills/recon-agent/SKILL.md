# Recon Agent

Especialista en recon-agent

## Instructions
Eres un experto de élite en recon-agent. Tu objetivo es ejecutar la siguiente metodología con precisión quirúrgica y eficiencia técnica.

---
name: recon-agent
description: Agente especializado en reconocimiento pasivo y activo para bug bounty. Usar para: (1) Enumeración de subdominios, (2) Descubrimiento DNS, (3) Análisis de certificados SSL, (4) Wayback Machine, (5) Identificación de tecnologías, (6) Escaneo de puertos, (7) OSINT general. Trigger: cuando se necesite mapear la superficie de ataque del target.
---

# 🔍 Recon Agent - Agente de Reconocimiento

## Objetivo
Realizar reconocimiento completo del target para identificar la superficie de ataque máxima posible.

## Capacidades

### 1. Reconocimiento Pasivo

#### DNS Enumeration
```python
import dns.resolver
import json
from datetime import datetime

def dns_enum(domain):
    """Enumerar registros DNS del dominio"""
    results = {
        "domain": domain,
        "timestamp": datetime.now().isoformat(),
        "records": {}
    }
    
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'SRV']
    
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            results["records"][rtype] = [str(r) for r in answers]
        except:
            pass
    
    return results
```

#### Subdomain Discovery
```bash
# Fuentes pasivas de subdominios
# 1. Certificate Transparency
curl -s "https://crt.sh/?q=%25.santelmo.org&output=json" | jq -r '.[].name_value' | sort -u

# 2. SecurityTrails (requiere API key)
# 3. VirusTotal (requiere API key)
# 4. Shodan (requiere API key)
# 5. Censys (requiere API key)
```

#### Certificate Analysis
```python
import ssl
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def analyze_cert(hostname, port=443):
    """Analizar certificado SSL/TLS"""
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert_bin = ssock.getpeercert(binary_form=True)
            cert = x509.load_der_x509_certificate(cert_bin, default_backend())
            
            return {
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "serial": cert.serial_number,
                "not_before": cert.not_valid_before.isoformat(),
                "not_after": cert.not_valid_after.isoformat(),
                "san": [ext.value for ext in cert.extensions 
                        if ext.oid._name == "subjectAltName"]
            }
```

#### Wayback Machine
```python
import waybackpy

def get_historical_urls(url, limit=100):
    """Obtener URLs históricas de Wayback Machine"""
    user_agent = "Mozilla/5.0"
    cdx = waybackpy.WaybackMachineCDXServerAPI(url, user_agent)
    
    urls = []
    for snapshot in cdx.snapshots():
        urls.append({
            "url": snapshot.original,
            "timestamp": snapshot.datetime_timestamp.isoformat(),
            "status": snapshot.statuscode
        })
        if len(urls) >= limit:
            break
    
    return urls
```

### 2. Reconocimiento Activo

#### Technology Detection
```python
import requests
from bs4 import BeautifulSoup
import re

def detect_technologies(url):
    """Detectar tecnologías usadas en el sitio"""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    
    r = requests.get(url, headers=headers, timeout=10)
    soup = BeautifulSoup(r.text, 'html.parser')
    
    techs = {
        "server": r.headers.get("Server", "Unknown"),
        "powered_by": r.headers.get("X-Powered-By", "Unknown"),
        "frameworks": [],
        "libraries": [],
        "analytics": [],
        "cdn": [],
        "security_headers": {}
    }
    
    # Detectar frameworks por patrones
    patterns = {
        "React": r"react|_react|__REACT",
        "Vue": r"vue\.js|__VUE",
        "Angular": r"ng-|angular",
        "jQuery": r"jquery",
        "Next.js": r"__NEXT_DATA__",
        "Nuxt": r"__NUXT__"
    }
    
    for name, pattern in patterns.items():
        if re.search(pattern, r.text, re.IGNORECASE):
            techs["frameworks"].append(name)
    
    # Headers de seguridad
    security_headers = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "X-XSS-Protection"
    ]
    
    for header in security_headers:
        techs["security_headers"][header] = r.headers.get(header, "Missing")
    
    return techs
```

#### Endpoint Discovery
```python
import re
from urllib.parse import urljoin, urlparse

def extract_endpoints(html, base_url):
    """Extraer endpoints de HTML y JavaScript"""
    endpoints = set()
    
    # Patrones para encontrar URLs
    patterns = [
        r'href=["\']([^"\']+)["\']',
        r'src=["\']([^"\']+)["\']',
        r'action=["\']([^"\']+)["\']',
        r'url\(["\']?([^"\')\s]+)["\']?\)',
        r'["\']/(api|v\d|graphql)[^"\']*["\']',
        r'fetch\(["\']([^"\']+)["\']',
        r'axios\.[a-z]+\(["\']([^"\']+)["\']'
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, html)
        for match in matches:
            if isinstance(match, tuple):
                match = match[0]
            
            # Construir URL completa
            if match.startswith('/'):
                full_url = urljoin(base_url, match)
            elif match.startswith('http'):
                full_url = match
            else:
                continue
            
            # Filtrar por dominio
            parsed = urlparse(full_url)
            if 'santelmo.org' in parsed.netloc:
                endpoints.add(full_url)
    
    return list(endpoints)
```

## Workflow de Reconocimiento

```
1. PASIVO (no genera tráfico hacia target)
   ├── DNS enumeration
   ├── Certificate Transparency (crt.sh)
   ├── Wayback Machine
   ├── WHOIS lookup
   └── Search engine dorking

2. ACTIVO (genera tráfico controlado)
   ├── Subdomain bruteforce
   ├── Port scanning (top 1000)
   ├── Technology fingerprinting
   ├── Endpoint discovery
   └── API enumeration
```

## Output Format

Todos los hallazgos se guardan en JSON para posterior análisis:

```json
{
  "target": "santelmo.org",
  "timestamp": "2024-01-15T10:30:00Z",
  "recon_type": "passive|active",
  "findings": {
    "subdomains": [],
    "dns_records": {},
    "technologies": {},
    "endpoints": [],
    "interesting_files": []
  },
  "notes": ""
}
```

## Archivos de Salida

- `01-recon/passive/dns/{domain}_dns.json`
- `01-recon/passive/certificates/{domain}_certs.json`
- `01-recon/passive/wayback/{domain}_history.json`
- `01-recon/active/subdomains/{domain}_subs.txt`
- `01-recon/active/technologies/{domain}_tech.json`
- `01-recon/active/endpoints/{domain}_endpoints.json`
- `01-recon/reports/recon_summary.md`

## 3. Subdomain Vulnerability Verification (2026)

### Cross-Subdomain Testing

```python
"""
Cuando se encuentra una vulnerabilidad en un subdominio,
verificar si existe en otros subdominios del mismo target.
Técnica usada en santelmo.org (FINDING-009)
"""

import requests
from concurrent.futures import ThreadPoolExecutor

def verify_vuln_across_subdomains(subdomains, vuln_endpoint, payload):
    """
    Verificar si una vulnerabilidad existe en múltiples subdominios

    Args:
        subdomains: Lista de subdominios a testear
        vuln_endpoint: Endpoint vulnerable (ej: "/en/news/tag-list/tag/{}/")
        payload: Payload a usar
    """
    results = {
        "vulnerable": [],
        "not_vulnerable": [],
        "errors": []
    }

    def test_subdomain(subdomain):
        url = f"https://{subdomain}{vuln_endpoint.format(payload)}"
        try:
            r = requests.get(url, timeout=10, allow_redirects=False)
            return {
                "subdomain": subdomain,
                "status": r.status_code,
                "vulnerable": r.status_code == 200 and payload in r.text,
                "redirects": r.status_code in [301, 302],
                "not_found": r.status_code == 404
            }
        except Exception as e:
            return {"subdomain": subdomain, "error": str(e)}

    with ThreadPoolExecutor(max_workers=5) as executor:
        for result in executor.map(test_subdomain, subdomains):
            if result.get("error"):
                results["errors"].append(result)
            elif result.get("vulnerable"):
                results["vulnerable"].append(result)
            else:
                results["not_vulnerable"].append(result)

    return results
```

### Application Fingerprinting por Subdominio

```python
def fingerprint_subdomain_apps(subdomains):
    """
    Identificar qué aplicación/framework corre en cada subdominio
    Importante para entender por qué una vuln existe en uno pero no en otro
    """
    app_signatures = {
        "wordpress": ["wp-content", "wp-includes", "WordPress"],
        "drupal": ["Drupal", "sites/default", "drupal.js"],
        "moodle": ["moodle", "Moodle", "/mod/"],
        "joomla": ["Joomla", "/components/", "com_content"],
        "laravel": ["laravel_session", "XSRF-TOKEN"],
        "django": ["csrfmiddlewaretoken", "django"],
        "rails": ["_session_id", "authenticity_token"],
        "aspnet": ["__VIEWSTATE", "ASP.NET"],
    }

    results = {}

    for subdomain in subdomains:
        try:
            r = requests.get(f"https://{subdomain}", timeout=10)
            detected = []

            for app, signatures in app_signatures.items():
                for sig in signatures:
                    if sig.lower() in r.text.lower() or sig in str(r.headers):
                        detected.append(app)
                        break

            results[subdomain] = {
                "server": r.headers.get("Server", "Unknown"),
                "powered_by": r.headers.get("X-Powered-By", "Unknown"),
                "detected_apps": list(set(detected)),
                "status": r.status_code
            }
        except Exception as e:
            results[subdomain] = {"error": str(e)}

    return results
```

### Endpoint Comparison

```python
def compare_endpoints_across_subdomains(subdomains, endpoints):
    """
    Comparar qué endpoints existen en cada subdominio

    Ejemplo de uso (santelmo.org):
    - /en/news/tag-list/tag/ existe solo en www.santelmo.org
    - Otros subdominios (adel, alumni) devuelven 404
    """
    comparison = {}

    for endpoint in endpoints:
        comparison[endpoint] = {}

        for subdomain in subdomains:
            url = f"https://{subdomain}{endpoint}"
            try:
                r = requests.head(url, timeout=5, allow_redirects=False)
                comparison[endpoint][subdomain] = {
                    "exists": r.status_code not in [404, 410],
                    "status": r.status_code,
                    "redirects_to": r.headers.get("Location") if r.status_code in [301, 302] else None
                }
            except:
                comparison[endpoint][subdomain] = {"error": True}

    return comparison
```

### Automated Vuln Propagation Test

```python
def test_vuln_propagation(primary_subdomain, vuln_details, all_subdomains):
    """
    Workflow completo para testear si una vulnerabilidad
    encontrada en un subdominio existe en otros

    vuln_details = {
        "type": "XSS",
        "endpoint": "/en/news/tag-list/tag/{payload}/",
        "payload": "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "detection_string": "<script>alert(1)</script>"
    }
    """
    report = {
        "original": primary_subdomain,
        "vulnerability": vuln_details["type"],
        "tested_subdomains": len(all_subdomains),
        "results": []
    }

    for subdomain in all_subdomains:
        url = f"https://{subdomain}{vuln_details['endpoint'].format(vuln_details['payload'])}"

        try:
            r = requests.get(url, timeout=10)

            result = {
                "subdomain": subdomain,
                "status_code": r.status_code,
                "endpoint_exists": r.status_code != 404,
                "payload_reflected": vuln_details["detection_string"] in r.text,
                "vulnerable": (
                    r.status_code == 200 and
                    vuln_details["detection_string"] in r.text
                )
            }

            # Razón de no vulnerabilidad
            if not result["vulnerable"]:
                if r.status_code == 404:
                    result["reason"] = "Endpoint no existe"
                elif r.status_code == 403:
                    result["reason"] = "WAF bloqueando"
                elif not result["payload_reflected"]:
                    result["reason"] = "Payload no reflejado (posible encoding)"
                else:
                    result["reason"] = "Aplicación diferente"

        except Exception as e:
            result = {"subdomain": subdomain, "error": str(e)}

        report["results"].append(result)

    # Resumen
    report["summary"] = {
        "vulnerable_subdomains": [r["subdomain"] for r in report["results"] if r.get("vulnerable")],
        "not_vulnerable": [r["subdomain"] for r in report["results"] if not r.get("vulnerable") and not r.get("error")],
        "errors": [r["subdomain"] for r in report["results"] if r.get("error")]
    }

    return report
```

---

## Integración con Orquestador

Este agente reporta al `main-orchestrator` y puede recibir instrucciones de:
- Expandir scope a subdominios específicos
- Profundizar en tecnologías detectadas
- Investigar endpoints interesantes
- **Verificar vulnerabilidades en otros subdominios** (nuevo)
- **Comparar aplicaciones entre subdominios** (nuevo)

---

**Versión**: 1.1
**Última actualización**: 2026-01-29
**Añadido**: Subdomain vulnerability verification, App fingerprinting


## Available Resources
- . (Directorio de la skill)
