---
name: owasp-orchestrator
description: Sub-orquestador especializado en testing sistemático OWASP Top 10 2021. Usar para: (1) Cobertura completa de A01-A10, (2) Testing de Broken Access Control, (3) Testing de Injection, (4) Testing de Auth Failures, (5) Testing de SSRF, (6) Generar matriz de cobertura OWASP. Trigger: cuando se necesite auditoría OWASP completa.
---

# 🛡️ OWASP Orchestrator - Orquestador OWASP Top 10

## Objetivo
Coordinar testing sistemático y completo de todas las categorías OWASP Top 10 2021.

## Categorías OWASP Top 10 2021

```
A01:2021 – Broken Access Control          ▶ auth-agent, api-agent
A02:2021 – Cryptographic Failures         ▶ auth-agent, recon-agent
A03:2021 – Injection                      ▶ injection-agent
A04:2021 – Insecure Design                ▶ manual + api-agent
A05:2021 – Security Misconfiguration      ▶ recon-agent, cloud-agent
A06:2021 – Vulnerable Components          ▶ recon-agent
A07:2021 – Auth Failures                  ▶ auth-agent
A08:2021 – Integrity Failures             ▶ api-agent, auth-agent
A09:2021 – Logging Failures               ▶ recon-agent
A10:2021 – SSRF                           ▶ injection-agent, cloud-agent
```

## Plan de Testing por Categoría

### A01: Broken Access Control
```python
a01_tests = {
    "name": "Broken Access Control",
    "agent": "auth-agent",
    "support": ["api-agent"],
    "tests": [
        {
            "id": "A01-01",
            "name": "IDOR - Horizontal Access",
            "description": "Acceder a recursos de otros usuarios del mismo nivel",
            "method": "test_horizontal_idor",
            "endpoints": [
                "/api/user/{id}/profile",
                "/api/user/{id}/bookings",
                "/api/user/{id}/payments",
                "/api/orders/{order_id}",
                "/api/reservations/{id}"
            ]
        },
        {
            "id": "A01-02",
            "name": "IDOR - Vertical Access",
            "description": "Acceder a funciones de admin siendo usuario normal",
            "method": "test_vertical_idor",
            "admin_endpoints": [
                "/api/admin/users",
                "/api/admin/config",
                "/api/admin/reports",
                "/internal/management"
            ]
        },
        {
            "id": "A01-03",
            "name": "Missing Function Level Access Control",
            "description": "Ejecutar funciones sin autorización",
            "method": "test_function_access",
            "functions": [
                "deleteUser", "modifyPrice", "exportData"
            ]
        },
        {
            "id": "A01-04",
            "name": "Path Traversal",
            "description": "Acceder a archivos fuera del directorio permitido",
            "method": "test_path_traversal",
            "payloads": ["../../../etc/passwd", "....//....//etc/passwd"]
        },
        {
            "id": "A01-05",
            "name": "Forced Browsing",
            "description": "Acceder a páginas no enlazadas",
            "method": "test_forced_browsing",
            "paths": ["/admin", "/debug", "/backup", "/api/docs"]
        }
    ],
    "output": "03-vulnerabilities/A01-broken-access-control/"
}
```

### A02: Cryptographic Failures
```python
a02_tests = {
    "name": "Cryptographic Failures",
    "agent": "auth-agent",
    "tests": [
        {
            "id": "A02-01",
            "name": "Sensitive Data in Transit",
            "description": "Datos sensibles sin HTTPS",
            "method": "check_ssl_configuration"
        },
        {
            "id": "A02-02",
            "name": "Weak SSL/TLS",
            "description": "Configuración SSL débil",
            "method": "test_ssl_strength",
            "checks": ["SSLv3", "TLS1.0", "weak_ciphers"]
        },
        {
            "id": "A02-03",
            "name": "Sensitive Data Exposure",
            "description": "PII expuesta en responses",
            "method": "check_sensitive_data_exposure",
            "patterns": ["credit_card", "ssn", "password"]
        },
        {
            "id": "A02-04",
            "name": "Weak Password Hashing",
            "description": "Algoritmos de hash débiles",
            "method": "analyze_password_storage"
        },
        {
            "id": "A02-05",
            "name": "Hardcoded Secrets",
            "description": "Secretos en código fuente",
            "method": "scan_for_secrets"
        }
    ],
    "output": "03-vulnerabilities/A02-cryptographic-failures/"
}
```

### A03: Injection
```python
a03_tests = {
    "name": "Injection",
    "agent": "injection-agent",
    "tests": [
        {
            "id": "A03-01",
            "name": "SQL Injection",
            "subtests": [
                {"name": "Error-based SQLi", "method": "test_error_sqli"},
                {"name": "Union-based SQLi", "method": "test_union_sqli"},
                {"name": "Blind Boolean SQLi", "method": "test_blind_boolean"},
                {"name": "Time-based SQLi", "method": "test_time_based"}
            ]
        },
        {
            "id": "A03-02",
            "name": "NoSQL Injection",
            "subtests": [
                {"name": "MongoDB Injection", "method": "test_mongodb_injection"},
                {"name": "Redis Injection", "method": "test_redis_injection"}
            ]
        },
        {
            "id": "A03-03",
            "name": "Command Injection",
            "method": "test_command_injection"
        },
        {
            "id": "A03-04",
            "name": "LDAP Injection",
            "method": "test_ldap_injection"
        },
        {
            "id": "A03-05",
            "name": "XPath Injection",
            "method": "test_xpath_injection"
        },
        {
            "id": "A03-06",
            "name": "Template Injection (SSTI)",
            "method": "test_ssti"
        }
    ],
    "output": "03-vulnerabilities/A03-injection/"
}
```

### A04: Insecure Design
```python
a04_tests = {
    "name": "Insecure Design",
    "agent": "api-agent",
    "tests": [
        {
            "id": "A04-01",
            "name": "Business Logic Flaws",
            "description": "Fallos en la lógica de negocio",
            "manual_tests": [
                "price_manipulation",
                "booking_bypass",
                "loyalty_abuse",
                "coupon_stacking"
            ]
        },
        {
            "id": "A04-02",
            "name": "Race Conditions",
            "method": "test_race_conditions",
            "targets": ["payment", "booking", "points_redemption"]
        },
        {
            "id": "A04-03",
            "name": "Missing Rate Limiting",
            "method": "test_rate_limiting"
        },
        {
            "id": "A04-04",
            "name": "Insufficient Anti-automation",
            "method": "test_automation_controls"
        }
    ],
    "output": "03-vulnerabilities/A04-insecure-design/"
}
```

### A05: Security Misconfiguration
```python
a05_tests = {
    "name": "Security Misconfiguration",
    "agent": "recon-agent",
    "support": ["cloud-agent"],
    "tests": [
        {
            "id": "A05-01",
            "name": "Default Credentials",
            "method": "test_default_creds"
        },
        {
            "id": "A05-02",
            "name": "Directory Listing",
            "method": "check_directory_listing"
        },
        {
            "id": "A05-03",
            "name": "Error Handling",
            "method": "check_error_disclosure"
        },
        {
            "id": "A05-04",
            "name": "Security Headers",
            "method": "check_security_headers",
            "headers": [
                "Strict-Transport-Security",
                "X-Content-Type-Options",
                "X-Frame-Options",
                "Content-Security-Policy",
                "X-XSS-Protection"
            ]
        },
        {
            "id": "A05-05",
            "name": "Cloud Misconfiguration",
            "method": "check_cloud_config",
            "agent": "cloud-agent"
        },
        {
            "id": "A05-06",
            "name": "CORS Misconfiguration",
            "method": "test_cors"
        },
        {
            "id": "A05-07",
            "name": "Debug Endpoints",
            "method": "find_debug_endpoints"
        }
    ],
    "output": "03-vulnerabilities/A05-security-misconfiguration/"
}
```

### A06: Vulnerable Components
```python
a06_tests = {
    "name": "Vulnerable and Outdated Components",
    "agent": "recon-agent",
    "tests": [
        {
            "id": "A06-01",
            "name": "JavaScript Libraries",
            "method": "scan_js_libraries",
            "check_cves": True
        },
        {
            "id": "A06-02",
            "name": "Server Software",
            "method": "identify_server_versions"
        },
        {
            "id": "A06-03",
            "name": "Framework Vulnerabilities",
            "method": "check_framework_cves"
        },
        {
            "id": "A06-04",
            "name": "Known CVEs",
            "method": "search_known_cves",
            "sources": ["nvd", "exploit-db"]
        }
    ],
    "output": "03-vulnerabilities/A06-vulnerable-components/"
}
```

### A07: Identification and Authentication Failures
```python
a07_tests = {
    "name": "Auth Failures",
    "agent": "auth-agent",
    "tests": [
        {
            "id": "A07-01",
            "name": "Credential Stuffing Protection",
            "method": "test_credential_stuffing"
        },
        {
            "id": "A07-02",
            "name": "Brute Force Protection",
            "method": "test_brute_force"
        },
        {
            "id": "A07-03",
            "name": "Weak Password Policy",
            "method": "test_password_policy"
        },
        {
            "id": "A07-04",
            "name": "Session Management",
            "subtests": [
                "session_fixation",
                "session_timeout",
                "concurrent_sessions",
                "session_invalidation"
            ]
        },
        {
            "id": "A07-05",
            "name": "MFA Bypass",
            "method": "test_mfa_bypass"
        },
        {
            "id": "A07-06",
            "name": "Password Reset Flaws",
            "method": "test_password_reset"
        },
        {
            "id": "A07-07",
            "name": "JWT Vulnerabilities",
            "method": "test_jwt_security"
        }
    ],
    "output": "03-vulnerabilities/A07-auth-failures/"
}
```

### A08: Software and Data Integrity Failures
```python
a08_tests = {
    "name": "Integrity Failures",
    "agent": "api-agent",
    "tests": [
        {
            "id": "A08-01",
            "name": "Insecure Deserialization",
            "method": "test_deserialization"
        },
        {
            "id": "A08-02",
            "name": "CI/CD Pipeline Issues",
            "method": "check_cicd_exposure"
        },
        {
            "id": "A08-03",
            "name": "Unsigned Updates",
            "method": "check_update_integrity"
        },
        {
            "id": "A08-04",
            "name": "Insecure Object References",
            "method": "test_object_references"
        }
    ],
    "output": "03-vulnerabilities/A08-integrity-failures/"
}
```

### A09: Security Logging and Monitoring Failures
```python
a09_tests = {
    "name": "Logging Failures",
    "agent": "recon-agent",
    "tests": [
        {
            "id": "A09-01",
            "name": "Log Injection",
            "method": "test_log_injection"
        },
        {
            "id": "A09-02",
            "name": "Sensitive Data in Logs",
            "method": "check_log_data_exposure"
        },
        {
            "id": "A09-03",
            "name": "Log File Access",
            "method": "find_exposed_logs"
        }
    ],
    "output": "03-vulnerabilities/A09-logging-failures/"
}
```

### A10: Server-Side Request Forgery (SSRF)
```python
a10_tests = {
    "name": "SSRF",
    "agent": "injection-agent",
    "support": ["cloud-agent"],
    "tests": [
        {
            "id": "A10-01",
            "name": "Basic SSRF",
            "method": "test_ssrf_basic",
            "targets": ["localhost", "127.0.0.1", "internal-service"]
        },
        {
            "id": "A10-02",
            "name": "Cloud Metadata SSRF",
            "method": "test_ssrf_metadata",
            "agent": "cloud-agent",
            "targets": ["169.254.169.254", "100.100.100.200"]
        },
        {
            "id": "A10-03",
            "name": "SSRF via URL Parameters",
            "method": "test_ssrf_params",
            "params": ["url", "uri", "path", "dest", "redirect", "img"]
        },
        {
            "id": "A10-04",
            "name": "SSRF Bypass Techniques",
            "method": "test_ssrf_bypass",
            "techniques": ["dns_rebinding", "protocol_smuggling", "ip_encoding"]
        }
    ],
    "output": "03-vulnerabilities/A10-ssrf/"
}
```

## Ejecución del Plan

```python
class OWASPOrchestrator:
    def __init__(self):
        self.categories = [
            a01_tests, a02_tests, a03_tests, a04_tests, a05_tests,
            a06_tests, a07_tests, a08_tests, a09_tests, a10_tests
        ]
        self.results = {}

    def run(self):
        """Ejecutar testing OWASP completo"""
        for category in self.categories:
            print(f"[*] Testing: {category['name']}")

            agent = get_agent(category["agent"])
            results = []

            for test in category["tests"]:
                print(f"    [>] {test['name']}")

                result = agent.execute(test)
                results.append(result)

                # Documentar hallazgos inmediatamente
                if result.get("findings"):
                    for finding in result["findings"]:
                        documentation_agent.log_finding(finding)

            self.results[category["name"]] = results

            # Guardar checkpoint
            self.save_checkpoint()

        return self.results

    def get_coverage_report(self):
        """Generar reporte de cobertura OWASP"""
        coverage = {}

        for category in self.categories:
            name = category["name"]
            total_tests = len(category["tests"])
            completed = len([r for r in self.results.get(name, []) if r])
            findings = sum(len(r.get("findings", [])) for r in self.results.get(name, []))

            coverage[name] = {
                "total_tests": total_tests,
                "completed": completed,
                "coverage_pct": (completed / total_tests) * 100,
                "findings": findings
            }

        return coverage
```

## Matriz de Cobertura

```
┌───────────────────────────────────────────────────────────────────┐
│                    OWASP TOP 10 COVERAGE MATRIX                   │
├────────────┬──────────┬──────────┬─────────┬─────────────────────┤
│ Category   │ Tests    │ Complete │ Finding │ Status              │
├────────────┼──────────┼──────────┼─────────┼─────────────────────┤
│ A01        │ 5        │ [ ]      │ 0       │ ⬜ Pending          │
│ A02        │ 5        │ [ ]      │ 0       │ ⬜ Pending          │
│ A03        │ 6        │ [ ]      │ 0       │ ⬜ Pending          │
│ A04        │ 4        │ [ ]      │ 0       │ ⬜ Pending          │
│ A05        │ 7        │ [ ]      │ 0       │ ⬜ Pending          │
│ A06        │ 4        │ [ ]      │ 0       │ ⬜ Pending          │
│ A07        │ 7        │ [ ]      │ 0       │ ⬜ Pending          │
│ A08        │ 4        │ [ ]      │ 0       │ ⬜ Pending          │
│ A09        │ 3        │ [ ]      │ 0       │ ⬜ Pending          │
│ A10        │ 4        │ [ ]      │ 0       │ ⬜ Pending          │
├────────────┼──────────┼──────────┼─────────┼─────────────────────┤
│ TOTAL      │ 49       │ 0        │ 0       │                     │
└────────────┴──────────┴──────────┴─────────┴─────────────────────┘
```
