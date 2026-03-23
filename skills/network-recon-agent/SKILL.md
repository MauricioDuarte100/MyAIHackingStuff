# Network Recon Agent

Especialista en network-recon-agent

## Instructions
Eres un experto de élite en network-recon-agent. Tu objetivo es ejecutar la siguiente metodología con precisión quirúrgica y eficiencia técnica.

---
name: network-recon-agent
description: Network and IP range reconnaissance specialist. Use for CIDR range scanning, IP enumeration, service discovery on network targets, banner grabbing, and infrastructure mapping. Triggers on IP ranges, CIDR notation, network testing, AWS/cloud IP targets.
---

# Network Recon Agent - Especialista en Reconocimiento de Red e IPs

## Objetivo
Realizar reconocimiento exhaustivo de rangos de IPs y redes, identificar servicios expuestos, mapear infraestructura, y descubrir activos en rangos CIDR autorizados para bug bounty.

## 1. IP Range Processing

### 1.1 CIDR Expansion y Validación
```python
import ipaddress
import socket
from typing import List, Dict, Generator
from concurrent.futures import ThreadPoolExecutor, as_completed

class IPRangeProcessor:
    """Procesa y expande rangos de IPs"""

    def __init__(self):
        self.valid_ips = []

    def expand_cidr(self, cidr: str) -> List[str]:
        """Expande un rango CIDR a lista de IPs"""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError as e:
            print(f"[!] Invalid CIDR: {cidr} - {e}")
            return []

    def parse_ip_list(self, ip_input: str) -> List[str]:
        """Parsea una lista mixta de IPs y CIDRs"""
        ips = []
        for item in ip_input.replace(',', '\n').split('\n'):
            item = item.strip()
            if not item:
                continue

            if '/' in item:
                # Es CIDR
                ips.extend(self.expand_cidr(item))
            elif '-' in item:
                # Es rango (ej: 192.168.1.1-192.168.1.10)
                ips.extend(self._expand_range(item))
            else:
                # Es IP individual
                try:
                    ipaddress.ip_address(item)
                    ips.append(item)
                except ValueError:
                    continue

        return list(set(ips))  # Eliminar duplicados

    def _expand_range(self, ip_range: str) -> List[str]:
        """Expande un rango de IPs (ej: 192.168.1.1-192.168.1.10)"""
        try:
            start_ip, end_ip = ip_range.split('-')
            start = ipaddress.ip_address(start_ip.strip())
            end = ipaddress.ip_address(end_ip.strip())

            ips = []
            current = start
            while current <= end:
                ips.append(str(current))
                current += 1
            return ips
        except:
            return []

    def filter_live_hosts(self, ips: List[str], timeout: float = 1.0) -> List[str]:
        """Filtra IPs que responden"""
        live_hosts = []

        def check_host(ip):
            try:
                socket.setdefaulttimeout(timeout)
                # Intentar conexión TCP a puertos comunes
                for port in [80, 443, 22]:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        result = sock.connect_ex((ip, port))
                        sock.close()
                        if result == 0:
                            return ip
                    except:
                        continue
                return None
            except:
                return None

        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(check_host, ip): ip for ip in ips}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    live_hosts.append(result)
                    print(f"[+] Live host: {result}")

        return live_hosts
```

### 1.2 Cloud IP Identification
```python
class CloudIPIdentifier:
    """Identifica si una IP pertenece a proveedores cloud"""

    # Rangos conocidos de proveedores cloud (simplificado)
    AWS_RANGES_PREFIX = [
        "3.", "13.", "15.", "18.", "34.", "35.", "44.", "50.", "52.",
        "54.", "99.", "107.", "174.", "175.", "176.", "177."
    ]

    AZURE_RANGES_PREFIX = [
        "13.", "20.", "23.", "40.", "51.", "52.", "65.", "70.",
        "104.", "137.", "138.", "157.", "168."
    ]

    GCP_RANGES_PREFIX = [
        "34.", "35.", "104.", "107.", "108.", "130.", "142.", "146."
    ]

    def identify_provider(self, ip: str) -> Dict:
        """Identifica el proveedor cloud de una IP"""
        result = {
            "ip": ip,
            "provider": "unknown",
            "is_cloud": False
        }

        # Verificación básica por prefijo
        for prefix in self.AWS_RANGES_PREFIX:
            if ip.startswith(prefix):
                result["provider"] = "AWS"
                result["is_cloud"] = True
                return result

        for prefix in self.AZURE_RANGES_PREFIX:
            if ip.startswith(prefix):
                result["provider"] = "Azure (possible)"
                result["is_cloud"] = True
                return result

        for prefix in self.GCP_RANGES_PREFIX:
            if ip.startswith(prefix):
                result["provider"] = "GCP (possible)"
                result["is_cloud"] = True
                return result

        return result

    def get_reverse_dns(self, ip: str) -> str:
        """Obtiene el DNS reverso de una IP"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return None
```

## 2. Port Scanning

### 2.0 Turbo Mode (Binary - Preferred for CTF)
**Trigger:** "Turbo scan", "Fast scan"

Uses native binaries (`nmap`, `rustscan`) for maximum speed. Overrides Python methods when speed is required.

```bash
# 1. Discovery (20s)
nmap -p- --min-rate=5000 -sS -Pn -v -n <ip> -oG all_ports.log

# 2. Targeted (Deep)
PORTS=$(grep Open all_ports.log | cut -d ' ' -f 2 | tr '\n' ',')
nmap -p$PORTS -sC -sV -Pn <ip> -oN targeted.nmap
```

### 2.1 Multi-Port Scanner (Python Fallback)
```python
import requests
from typing import List, Dict, Tuple

class NetworkScanner:
    """Scanner de red para bug bounty"""

    # Puertos comunes para web y servicios
    WEB_PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000, 9090]
    API_PORTS = [8080, 8443, 3000, 5000, 8000, 4000, 9000]
    DB_PORTS = [3306, 5432, 27017, 6379, 1433, 1521]
    ADMIN_PORTS = [8080, 8443, 9090, 9000, 10000, 2082, 2083]
    ALL_COMMON_PORTS = list(set(WEB_PORTS + API_PORTS + DB_PORTS + ADMIN_PORTS))

    def __init__(self, timeout: int = 3):
        self.timeout = timeout

    def scan_ip(self, ip: str, ports: List[int] = None) -> Dict:
        """Escanea una IP en busca de puertos abiertos"""
        ports = ports or self.ALL_COMMON_PORTS
        results = {
            "ip": ip,
            "open_ports": [],
            "services": []
        }

        def check_port(port: int) -> Tuple[int, bool]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                return (port, result == 0)
            except:
                return (port, False)

        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = [executor.submit(check_port, port) for port in ports]
            for future in as_completed(futures):
                port, is_open = future.result()
                if is_open:
                    results["open_ports"].append(port)

        # Identificar servicios en puertos abiertos
        for port in results["open_ports"]:
            service_info = self._identify_service(ip, port)
            results["services"].append(service_info)

        return results

    def _identify_service(self, ip: str, port: int) -> Dict:
        """Identifica el servicio en un puerto abierto"""
        service = {
            "port": port,
            "protocol": "tcp",
            "service": "unknown",
            "banner": None,
            "http": False
        }

        # Intentar conexión HTTP/HTTPS
        for protocol in ['https', 'http']:
            url = f"{protocol}://{ip}:{port}" if port not in [80, 443] else f"{protocol}://{ip}"
            try:
                resp = requests.get(url, timeout=self.timeout, verify=False,
                                   allow_redirects=False)
                service["http"] = True
                service["protocol"] = protocol
                service["status_code"] = resp.status_code
                service["server"] = resp.headers.get('server', 'N/A')
                service["headers"] = dict(resp.headers)
                break
            except requests.exceptions.SSLError:
                if protocol == 'https':
                    service["ssl_error"] = True
                continue
            except:
                continue

        # Banner grabbing para servicios no-HTTP
        if not service["http"]:
            service["banner"] = self._grab_banner(ip, port)

        return service

    def _grab_banner(self, ip: str, port: int, timeout: int = 3) -> str:
        """Captura el banner de un servicio"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))

            # Enviar un pequeño probe
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")

            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            return banner[:500] if banner else None
        except:
            return None
```

## 3. Service Discovery on IPs

### 3.1 Web Service Enumeration
```python
class WebServiceDiscovery:
    """Descubre servicios web en IPs"""

    COMMON_PATHS = [
        "/", "/api", "/api/v1", "/api/v2",
        "/health", "/status", "/info", "/version",
        "/docs", "/swagger", "/redoc", "/openapi.json",
        "/admin", "/login", "/dashboard",
        "/graphql", "/graphiql",
        "/.well-known/", "/robots.txt", "/sitemap.xml"
    ]

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def discover_web_services(self, ip: str, ports: List[int]) -> List[Dict]:
        """Descubre servicios web en una IP"""
        services = []

        for port in ports:
            for protocol in ['https', 'http']:
                base_url = f"{protocol}://{ip}:{port}" if port not in [80, 443] else f"{protocol}://{ip}"

                try:
                    resp = self.session.get(base_url, timeout=self.timeout,
                                           verify=False, allow_redirects=False)

                    service = {
                        "ip": ip,
                        "port": port,
                        "protocol": protocol,
                        "base_url": base_url,
                        "status_code": resp.status_code,
                        "server": resp.headers.get('server', 'N/A'),
                        "content_type": resp.headers.get('content-type', ''),
                        "title": self._extract_title(resp.text),
                        "technologies": self._detect_technologies(resp),
                        "interesting_paths": []
                    }

                    # Probar paths comunes
                    for path in self.COMMON_PATHS:
                        path_info = self._check_path(base_url, path)
                        if path_info.get("accessible"):
                            service["interesting_paths"].append(path_info)

                    services.append(service)
                    break  # Si funciona con un protocolo, no probar el otro

                except requests.exceptions.SSLError:
                    continue
                except:
                    continue

        return services

    def _check_path(self, base_url: str, path: str) -> Dict:
        """Verifica si un path es accesible"""
        url = f"{base_url}{path}"
        try:
            resp = self.session.get(url, timeout=self.timeout, verify=False)
            return {
                "path": path,
                "url": url,
                "accessible": resp.status_code == 200,
                "status_code": resp.status_code,
                "size": len(resp.text)
            }
        except:
            return {"path": path, "accessible": False}

    def _extract_title(self, html: str) -> str:
        """Extrae el título de una página"""
        import re
        match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
        return match.group(1).strip() if match else "N/A"

    def _detect_technologies(self, resp) -> List[str]:
        """Detecta tecnologías basándose en headers y contenido"""
        techs = []
        server = resp.headers.get('server', '').lower()
        powered_by = resp.headers.get('x-powered-by', '').lower()
        content = resp.text.lower()[:5000]

        tech_indicators = {
            "nginx": server,
            "apache": server,
            "iis": server,
            "cloudflare": server + resp.headers.get('cf-ray', ''),
            "fastapi": server + content,
            "django": powered_by + content,
            "flask": powered_by + content,
            "express": powered_by,
            "php": powered_by,
            "asp.net": powered_by,
            "tomcat": server,
            "spring": content
        }

        for tech, source in tech_indicators.items():
            if tech in source:
                techs.append(tech)

        return techs
```

## 4. AWS-Specific Reconnaissance

### 4.1 AWS IP Testing
```python
class AWSIPRecon:
    """Reconocimiento específico para IPs de AWS"""

    AWS_METADATA_ENDPOINTS = [
        "/latest/meta-data/",
        "/latest/user-data/",
        "/latest/dynamic/instance-identity/document"
    ]

    def test_ssrf_to_metadata(self, target_url: str) -> Dict:
        """Testea SSRF hacia AWS metadata service"""
        results = {
            "target": target_url,
            "metadata_accessible": False,
            "findings": []
        }

        # Probar SSRF hacia metadata
        metadata_url = "http://169.254.169.254"

        ssrf_params = [
            f"url={metadata_url}",
            f"redirect={metadata_url}",
            f"link={metadata_url}",
            f"src={metadata_url}",
            f"dest={metadata_url}",
            f"uri={metadata_url}",
            f"path={metadata_url}",
            f"file={metadata_url}",
        ]

        session = requests.Session()

        for param in ssrf_params:
            test_url = f"{target_url}?{param}"
            try:
                resp = session.get(test_url, timeout=10, verify=False)
                if "ami-id" in resp.text or "instance-id" in resp.text:
                    results["metadata_accessible"] = True
                    results["findings"].append({
                        "parameter": param.split('=')[0],
                        "payload": param,
                        "response_preview": resp.text[:500]
                    })
            except:
                continue

        return results

    def identify_aws_services(self, ip: str, ports: List[int]) -> Dict:
        """Identifica servicios AWS expuestos"""
        services = {
            "ip": ip,
            "aws_services": []
        }

        # Patrones de servicios AWS
        aws_patterns = {
            "s3": ["AmazonS3", "x-amz-", "s3.amazonaws.com"],
            "api_gateway": ["x-amzn-requestid", "x-amz-apigw-id"],
            "cloudfront": ["x-amz-cf-", "cloudfront"],
            "elb": ["awselb", "ELB"],
            "lambda": ["x-amzn-remapped-", "lambda"],
            "cognito": ["cognito", "x-amzn-cognito"]
        }

        session = requests.Session()

        for port in ports:
            for protocol in ['https', 'http']:
                url = f"{protocol}://{ip}:{port}" if port not in [80, 443] else f"{protocol}://{ip}"

                try:
                    resp = session.get(url, timeout=10, verify=False)
                    headers_str = str(resp.headers).lower()
                    content = resp.text.lower()[:2000]

                    for service, patterns in aws_patterns.items():
                        if any(p.lower() in headers_str or p.lower() in content
                               for p in patterns):
                            services["aws_services"].append({
                                "service": service,
                                "port": port,
                                "url": url
                            })
                except:
                    continue

        return services
```

## 5. Network Workflow

```yaml
network_recon_workflow:
  phase_1_preparation:
    - parse_ip_input
    - expand_cidr_ranges
    - identify_cloud_providers
    - get_reverse_dns

  phase_2_host_discovery:
    - ping_sweep
    - filter_live_hosts
    - initial_port_scan

  phase_3_service_identification:
    - detailed_port_scan
    - banner_grabbing
    - technology_fingerprinting

  phase_4_web_discovery:
    - enumerate_web_services
    - check_common_paths
    - discover_api_documentation
    - test_admin_endpoints

  phase_5_aws_specific:
    - identify_aws_services
    - test_metadata_ssrf
    - check_s3_misconfigs
```

## 6. Output Format

```json
{
  "scan_date": "2026-01-29T20:00:00Z",
  "target_range": "3.133.230.0/24",
  "scope": "Under Armour Bug Bounty - AWS IPs",
  "live_hosts": [
    {
      "ip": "3.133.230.28",
      "reverse_dns": "ec2-3-133-230-28.us-east-2.compute.amazonaws.com",
      "cloud_provider": "AWS",
      "open_ports": [80],
      "services": [
        {
          "port": 80,
          "protocol": "http",
          "server": "uvicorn",
          "technology": "fastapi"
        }
      ],
      "web_paths": [
        {
          "path": "/docs",
          "status": 200,
          "type": "swagger_ui"
        }
      ]
    }
  ],
  "statistics": {
    "total_ips_scanned": 254,
    "live_hosts_found": 5,
    "web_services_found": 3,
    "vulnerabilities_found": 2
  }
}
```

## 7. Archivos de Salida

```
01-recon/
├── active/
│   └── network/
│       ├── cidr-expansion.json
│       ├── live-hosts.json
│       ├── port-scan-results.json
│       └── service-fingerprints.json
└── reports/
    └── network-recon-summary.md
```

## 8. Integración con Otros Agentes

| Agente | Integración |
|--------|-------------|
| **recon-agent** | Proporciona IPs de subdominios resueltos |
| **service-enumeration-agent** | Testing detallado de servicios descubiertos |
| **cloud-agent** | Análisis específico de servicios AWS |
| **api-agent** | Testing de APIs en IPs descubiertas |
| **soap-security-agent** | Testing de SOAP services encontrados |
| **documentation-agent** | Documenta infraestructura descubierta |

---

**Versión**: 1.0
**Última actualización**: 2026-01-29
**Basado en**: Under Armour Bug Bounty - Network Testing (IPs en scope)


## Available Resources
- . (Directorio de la skill)
