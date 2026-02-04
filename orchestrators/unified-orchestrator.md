# 🎯 UNIFIED ORCHESTRATOR v2.0
## Coordinación Total de 18 Agentes Especializados + 6 Externos para Bug Bounty

---

## ARQUITECTURA UNIFICADA v2.0

```
                              ┌─────────────────────────────────┐
                              │      UNIFIED ORCHESTRATOR       │
                              │   "El Cerebro del Assessment"   │
                              │          VERSION 2.0            │
                              └───────────────┬─────────────────┘
                                              │
              ┌───────────────────────────────┼───────────────────────────────┐
              │                               │                               │
              ▼                               ▼                               ▼
    ┌─────────────────┐           ┌─────────────────┐           ┌─────────────────┐
    │  INTERNAL SKILLS │           │ EXTERNAL AGENTS │           │  ORCHESTRATORS  │
    │  (18 Especialistas)│         │  (6 Generalistas)│          │ (4 Coordinadores)│
    └─────────────────┘           └─────────────────┘           └─────────────────┘
              │                               │                               │
    ┌─────────┴─────────┐            ┌───────┴───────┐            ┌─────────┴─────────┐
    ▼                   ▼            ▼               ▼            ▼                   ▼
┌─────────────┐  ┌─────────────┐  ┌────────┐  ┌────────┐  ┌─────────┐  ┌─────────┐
│   CORE      │  │  ADVANCED   │  │ OFFENSE│  │DEFENSE │  │  MAIN   │  │  OWASP  │
│  AGENTS     │  │   AGENTS    │  │ AGENTS │  │ AGENTS │  │  ORCH   │  │  ORCH   │
├─────────────┤  ├─────────────┤  ├────────┤  ├────────┤  ├─────────┤  ├─────────┤
│recon-agent  │  │xss-agent    │  │pentest │  │sec-    │  │  API    │  │UNIFIED  │
│inject-agent │  │waf-bypass   │  │er      │  │auditor │  │  ORCH   │  │  ORCH   │
│api-agent    │  │advanced-web │  │code    │  │backend │  └─────────┘  └─────────┘
│cloud-agent  │  │race-cond    │  │review  │  │archit  │
│auth-agent   │  │subdomain    │  └────────┘  └────────┘
│doc-agent    │  │mobile-sec   │
├─────────────┤  │ai-security  │
│  🆕 NEW     │  │recon-auto   │
├─────────────┤  └─────────────┘
│soap-sec     │
│service-enum │
│error-disc   │
│network-recon│
└─────────────┘
```

---

## MATRIZ DE RESPONSABILIDADES

### Por Fase del Assessment

| Fase | Agentes Primarios | Agentes de Soporte | Orchestrator |
|------|-------------------|-------------------|--------------|
| **Recon** | recon-agent, network-recon-agent, backend-architect | python-pro, recon-automation-agent | main |
| **Mapping** | api-agent, service-enumeration-agent, backend-architect | recon-agent | api |
| **Auth Testing** | auth-agent, security-auditor | api-security-audit | owasp |
| **Injection** | injection-agent, penetration-tester | security-auditor, soap-security-agent | owasp |
| **API Testing** | api-agent, api-security-audit, service-enumeration-agent | penetration-tester, soap-security-agent | api |
| **Cloud** | cloud-agent, penetration-tester | security-auditor, network-recon-agent | main |
| **Exploitation** | penetration-tester, injection-agent, advanced-web-agent | python-pro | main |
| **Reporting** | documentation-agent, code-reviewer, error-disclosure-agent | python-pro | main |
| **🆕 Network** | network-recon-agent, service-enumeration-agent | cloud-agent, penetration-tester | main |
| **🆕 SOAP/XML** | soap-security-agent, injection-agent | api-agent, penetration-tester | api |
| **🆕 Error Analysis** | error-disclosure-agent, service-enumeration-agent | api-agent, documentation-agent | owasp |

### Por Tipo de Vulnerabilidad

| Vulnerabilidad | Agente Principal | Agente Validación | Agente PoC |
|----------------|------------------|-------------------|------------|
| SQL Injection | injection-agent | security-auditor | python-pro |
| XSS | xss-agent, injection-agent | code-reviewer | penetration-tester |
| IDOR | auth-agent | api-security-audit | penetration-tester |
| SSRF | cloud-agent | penetration-tester | python-pro |
| JWT Issues | auth-agent | security-auditor | api-security-audit |
| GraphQL | api-agent | api-security-audit | penetration-tester |
| Auth Bypass | auth-agent | penetration-tester | security-auditor |
| Cloud Misconfig | cloud-agent | security-auditor | penetration-tester |
| 🆕 **SOAP/XXE** | soap-security-agent | injection-agent | penetration-tester |
| 🆕 **Service Exposure** | service-enumeration-agent | api-security-audit | penetration-tester |
| 🆕 **Error Disclosure** | error-disclosure-agent | security-auditor | documentation-agent |
| 🆕 **Network Services** | network-recon-agent | service-enumeration-agent | cloud-agent |
| WAF Bypass | waf-bypass-agent | xss-agent | penetration-tester |
| HTTP Smuggling | advanced-web-agent | penetration-tester | python-pro |
| Race Conditions | race-condition-agent | penetration-tester | python-pro |
| Subdomain Takeover | subdomain-takeover-agent | recon-agent | penetration-tester |
| AI/LLM Vulns | ai-security-agent | security-auditor | penetration-tester |
| Mobile Security | mobile-security-agent | api-agent | penetration-tester |
| 🆕 **Host Header Injection** | advanced-web-agent | **exploitability-validator** | documentation-agent |
| 🆕 **CORS Misconfig** | api-agent | **exploitability-validator** | documentation-agent |
| 🆕 **Open Redirect** | auth-agent | **exploitability-validator** | documentation-agent |
| 🆕 **CSRF** | auth-agent | **exploitability-validator** | documentation-agent |

---

## WORKFLOW UNIFICADO

### FASE 1: RECONNAISSANCE
```yaml
primary_agents:
  - recon-agent:
      tasks:
        - DNS enumeration
        - Subdomain discovery
        - Technology fingerprinting
        - Historical endpoints (Wayback)
  - 🆕 network-recon-agent:
      tasks:
        - CIDR range expansion (204.29.196.0/23)
        - IP enumeration for AWS targets
        - Cloud provider identification
        - Banner grabbing on discovered hosts
        - Multi-port scanning (80, 443, 8080, 8443)
  - backend-architect:
      tasks:
        - Infer system architecture
        - Identify service boundaries
        - Map technology stack
        - Predict API patterns

support_agents:
  - python-pro:
      tasks:
        - Write custom recon scripts
        - Automate data collection
  - recon-automation-agent:
      tasks:
        - Full automation pipeline
        - Continuous monitoring

output:
  - 01-recon/passive/dns-records.json
  - 01-recon/passive/subdomains.json
  - 01-recon/active/technologies.json
  - 01-recon/active/ip-scan-results.json
  - 01-recon/active/cidr-enumeration.json
  - 01-recon/architecture-analysis.md
```

### FASE 2: MAPPING & ANALYSIS
```yaml
primary_agents:
  - api-agent:
      tasks:
        - REST endpoint discovery
        - GraphQL introspection
        - WebSocket identification
        - Parameter enumeration
  - 🆕 service-enumeration-agent:
      tasks:
        - API documentation discovery (Swagger, OpenAPI, ReDoc)
        - Admin endpoint scanning (/admin/*, /debug/*, /api-docs)
        - Unauthenticated service access testing
        - Debug endpoint detection
        - Health/status endpoint enumeration
  - api-security-audit:
      tasks:
        - Auth mechanism analysis
        - Rate limit testing
        - Error handling review
        - Header analysis
  - 🆕 soap-security-agent:
      tasks:
        - WSDL discovery and parsing
        - SOAP endpoint enumeration
        - XML service detection

support_agents:
  - backend-architect:
      tasks:
        - API design review
        - Microservice boundary analysis
  - code-reviewer:
      tasks:
        - Review JS bundles
        - Analyze client-side logic

output:
  - 02-mapping/api-endpoints.json
  - 02-mapping/graphql-schema.json
  - 02-mapping/swagger-docs-found.json
  - 02-mapping/wsdl-services.json
  - 02-mapping/admin-endpoints.json
  - 02-mapping/auth-flows.md
  - 05-api-testing/security-baseline.md
```

### FASE 3: VULNERABILITY TESTING
```yaml
# === OWASP A01: Broken Access Control ===
agents:
  - auth-agent: IDOR testing, privilege escalation
  - api-security-audit: Authorization bypass
  - penetration-tester: Access control exploitation
  - 🆕 service-enumeration-agent: Unauthenticated admin endpoints

# === OWASP A02: Cryptographic Failures ===
agents:
  - security-auditor: TLS analysis, encryption review
  - api-security-audit: Sensitive data exposure
  - auth-agent: Token security analysis

# === OWASP A03: Injection ===
agents:
  - injection-agent: SQLi, NoSQLi, SSTI, Command injection
  - penetration-tester: Exploitation and escalation
  - python-pro: Custom injection payloads
  - 🆕 soap-security-agent: XXE, SOAP injection, WS-Security bypass

# === OWASP A05: Security Misconfiguration ===
agents:
  - 🆕 service-enumeration-agent: Debug endpoints, API docs exposure
  - 🆕 error-disclosure-agent: Verbose error messages, stack traces
  - cloud-agent: Cloud misconfigurations
  - security-auditor: Configuration review

# === OWASP A04-A10 ===
agents:
  - security-auditor: Systematic OWASP coverage
  - penetration-tester: Active exploitation
  - code-reviewer: Source code analysis

# === 🆕 ADDITIONAL TESTING ===
agents:
  - 🆕 error-disclosure-agent:
      tasks:
        - Resource enumeration via error differences
        - Stack trace technology disclosure
        - Verbose error information leakage
        - Collection/user enumeration
  - 🆕 soap-security-agent:
      tasks:
        - WSDL security testing
        - XXE via SOAP
        - WS-Security bypass
        - Unauthenticated SOAP operations
  - 🆕 network-recon-agent:
      tasks:
        - Service discovery on IP ranges
        - Banner analysis
        - Version fingerprinting

parallel_execution:
  - Group 1: A01 + A07 (access/auth) - auth-agent + security-auditor + service-enumeration-agent
  - Group 2: A03 (injection) - injection-agent + penetration-tester + soap-security-agent
  - Group 3: A05 + A06 (config/components) - cloud-agent + code-reviewer + error-disclosure-agent
  - Group 4: 🆕 Network/Services - network-recon-agent + service-enumeration-agent

output:
  - 03-vulnerabilities/A01-A10 findings
  - 03-vulnerabilities/additional/soap-findings.md
  - 03-vulnerabilities/additional/error-disclosure-findings.md
  - 06-evidence/screenshots/
  - 06-evidence/requests/
```

### FASE 4: EXPLOITATION & POC (2-4h)
```yaml
primary_agents:
  - penetration-tester:
      tasks:
        - Develop working exploits
        - Chain vulnerabilities
        - Demonstrate impact
        - Document attack paths
  - python-pro:
      tasks:
        - Write professional PoC scripts
        - Create automation tools
        - Ensure reproducibility

validation_agents:
  - code-reviewer:
      tasks:
        - Review exploit code quality
        - Ensure safe execution
        - Check for edge cases
  - security-auditor:
      tasks:
        - Validate CVSS scoring
        - Confirm severity classification
        - Review remediation advice

output:
  - 06-evidence/poc/exploit-*.py
  - 06-evidence/poc/README.md
```

### 🆕 FASE 4.5: VALIDACIÓN DE EXPLOTABILIDAD (OBLIGATORIA)
```yaml
# Esta fase es CRÍTICA - aprendida de rechazos Bugcrowd

purpose: "Validar que cada vulnerabilidad tiene un vector de ataque PRÁCTICO antes de reportar"

primary_agents:
  - 🆕 exploitability-validator:
      tasks:
        - Validar vectores prácticos para cada finding
        - Filtrar vulnerabilidades "teóricas" sin impacto real
        - Confirmar que el PoC funciona desde BROWSER, no solo curl
        - Responder "Como atacante, YO PUDE [X]"

vulnerability_specific_validation:
  host_header_injection:
    tests_required:
      - "Cache headers (no-cache = no exploit)"
      - "X-Forwarded-Host reflection"
      - "X-Host reflection"
      - "Password reset poisoning"
    decision: "Si NINGUNO funciona → NO reportar"
    ejemplo_rechazado: "UA-2026-004 - transfer.underarmour.com"

  cors_misconfiguration:
    tests_required:
      - "Origin reflection (attacker.com)"
      - "Null origin acceptance"
      - "Credentials allowed"
      - "Sensitive data in response"
    decision: "Necesita: reflected origin AND credentials AND sensitive data"

  open_redirect:
    tests_required:
      - "Redirect automático (302/301)"
      - "Bypass de validación"
      - "OAuth chain posible"
    decision: "Solo reportar si redirect automático O combinable con OAuth"

  csrf:
    tests_required:
      - "SameSite cookies (None = exploitable)"
      - "CSRF token presente"
      - "Auth via cookie (not header)"
      - "Acción sensible disponible"
    decision: "Necesita: cookies sin SameSite AND sin token AND acción crítica"

# Regla de oro
golden_rule: |
  Si no podés completar la frase "Como atacante, YO PUDE [acción específica]"
  con un vector de ataque REAL (no curl con headers modificados),
  entonces NO es reportable.

output:
  - findings filtrados (solo los explotables)
  - validation-report.md con decisiones
  - rechazados.md (para referencia futura)
```

### FASE 5: REPORTING
```yaml
primary_agents:
  - documentation-agent:
      tasks:
        - Generate executive summary
        - Create technical report
        - Export findings (JSON, CSV, MD)
        - Bug bounty platform formatting
        - 🆕 VALIDAR contra reglas de calidad Bugcrowd
  - code-reviewer:
      tasks:
        - Review report quality
        - Validate technical accuracy
        - Check PoC reproducibility

# 🚨 VALIDACIÓN OBLIGATORIA ANTES DE SUBMIT
validation_rules:
  - NO especulación: Eliminar "may contain", "could potentially", "worst case"
  - SOLO hechos confirmados: Cada claim debe tener request/response
  - Severidad justificada: CVSS basado en impacto DEMOSTRADO, no teórico
  - Enumeración honesta: Solo listar items con evidencia real

output:
  - 07-reports/executive-summary.md
  - 07-reports/technical-report.md
  - 07-reports/findings-export.json
  - 07-reports/platform-submission.md
```

---

## SISTEMA DE COMUNICACIÓN ENTRE AGENTES

### Message Queue
```python
class AgentMessage:
    """Mensaje entre agentes"""
    def __init__(self, from_agent, to_agent, message_type, payload):
        self.id = str(uuid.uuid4())
        self.timestamp = datetime.now().isoformat()
        self.from_agent = from_agent
        self.to_agent = to_agent
        self.message_type = message_type  # FINDING, REQUEST, RESPONSE, ALERT
        self.payload = payload
        self.priority = "NORMAL"  # LOW, NORMAL, HIGH, CRITICAL

# Tipos de mensajes
MESSAGE_TYPES = {
    "FINDING": "Nueva vulnerabilidad descubierta",
    "REQUEST": "Solicitud de análisis adicional",
    "RESPONSE": "Respuesta a solicitud",
    "ALERT": "Hallazgo crítico - acción inmediata",
    "HANDOFF": "Transferir tarea a otro agente",
    "COMPLETE": "Tarea completada"
}
```

### Shared State
```python
SHARED_STATE = {
    "target": "santelmo.org",
    "phase": "TESTING",
    "findings": [],
    "endpoints_discovered": [],
    "endpoints_tested": [],
    "current_tasks": {},
    "agent_status": {
        "recon-agent": "IDLE",
        "injection-agent": "ACTIVE",
        "penetration-tester": "WAITING",
        # ... etc
    }
}
```

---

## REGLAS DE ESCALACIÓN

### Cuándo Escalar entre Agentes

```yaml
escalation_rules:
  # Encontró endpoint → Analizar
  - trigger: "recon-agent finds new API endpoint"
    action: "Notify api-agent for testing"

  # Encontró vulnerabilidad potencial → Explotar
  - trigger: "injection-agent confirms SQLi"
    action: "Handoff to penetration-tester for exploitation"

  # Necesita código → Python expert
  - trigger: "Any agent needs custom tool"
    action: "Request python-pro to write script"

  # Hallazgo crítico → Documentar inmediatamente
  - trigger: "CVSS >= 9.0"
    action: "Alert documentation-agent, pause non-critical tasks"

  # Duda sobre arquitectura → Consultar
  - trigger: "Unclear service boundary"
    action: "Consult backend-architect for analysis"

  # Necesita validación de seguridad → Auditor
  - trigger: "Uncertain about vulnerability validity"
    action: "Request security-auditor validation"

  # 🆕 Encontró IP o CIDR → Network recon
  - trigger: "New IP address or CIDR range to scan"
    action: "Notify network-recon-agent for enumeration"

  # 🆕 Encontró Swagger/OpenAPI → Service enumeration
  - trigger: "API documentation discovered"
    action: "Handoff to service-enumeration-agent for analysis"

  # 🆕 Encontró WSDL/SOAP → SOAP testing
  - trigger: "WSDL or SOAP service discovered"
    action: "Handoff to soap-security-agent for XXE and auth testing"

  # 🆕 Error messages con info sensible → Error disclosure
  - trigger: "Verbose error messages or stack traces found"
    action: "Notify error-disclosure-agent for enumeration attacks"

  # 🆕 Diferentes errores por recurso → Enumeration
  - trigger: "Error messages vary by resource existence"
    action: "Alert error-disclosure-agent for collection/user enumeration"

  # 🆕 Admin endpoint sin auth → Critical escalation
  - trigger: "Unauthenticated admin endpoint found"
    action: "CRITICAL: Document immediately, validate with penetration-tester"

  # 🆕 Vulnerabilidad "teórica" encontrada → Validar explotabilidad
  - trigger: "Host Header Injection, CORS, Open Redirect, CSRF detected"
    action: "MANDATORY: Send to exploitability-validator BEFORE documenting"

  # 🆕 Exploitability validation failed → Do NOT report
  - trigger: "exploitability-validator returns NO_PRACTICAL_VECTOR"
    action: "DISCARD finding, log to rejected-findings.md"

  # 🆕 Exploitability validation passed → Continue to documentation
  - trigger: "exploitability-validator returns EXPLOITABLE"
    action: "Proceed to documentation-agent with validated PoC"
```

### Priority Matrix

| Evento | Prioridad | Acción |
|--------|-----------|--------|
| RCE encontrado | CRITICAL | Pausar todo, documentar, explotar |
| SQLi con data dump | CRITICAL | Documentar inmediatamente |
| Auth bypass admin | CRITICAL | Validar y documentar |
| 🆕 **Unauthenticated admin endpoint** | **CRITICAL** | service-enumeration-agent → documentation-agent |
| 🆕 **XXE con SSRF** | **CRITICAL** | soap-security-agent → penetration-tester |
| IDOR con PII | HIGH | Documentar en 1h |
| Stored XSS | HIGH | Validar impacto |
| SSRF interno | HIGH | Escalar a cloud-agent |
| 🆕 **SOAP service sin auth** | **HIGH** | soap-security-agent → auth-agent → doc |
| 🆕 **Collection enumeration (sensitive)** | **HIGH** | error-disclosure-agent → doc |
| 🆕 **Exposed Swagger with admin routes** | **HIGH** | service-enumeration-agent → auth-agent |
| Reflected XSS | MEDIUM | Documentar en 4h |
| 🆕 **Error-based tech disclosure** | **MEDIUM** | error-disclosure-agent → doc |
| 🆕 **Open service on AWS IP** | **MEDIUM** | network-recon-agent → service-enumeration-agent |
| Info disclosure | LOW | Documentar al final |
| 🆕 **Version disclosure** | **LOW** | Documentar como observación |

---

## INVOCACIÓN DE AGENTES

### Comando Unificado
```bash
# Ejecutar assessment completo
antigravity --config unified-orchestrator.md "Iniciar bug bounty assessment completo"

# Ejecutar fase específica
antigravity --config unified-orchestrator.md "Ejecutar solo Fase 1: Reconocimiento"

# Invocar agente específico
antigravity --agent penetration-tester "Explotar SQLi en /api/search?q="

# Cadena de agentes
antigravity --agent recon-agent "Enumerar subdominios" | \
antigravity --agent api-agent "Descubrir endpoints" | \
antigravity --agent injection-agent "Testear inyecciones"
```

### Delegación Automática
```markdown
## Prompt para Delegación

Cuando encuentres una situación que requiere otro agente:

1. Identifica el agente apropiado según la matriz de responsabilidades
2. Prepara el contexto necesario (findings, endpoints, payloads)
3. Delega con instrucciones claras:
   
   "Delegando a [AGENTE]: [TAREA]
   Contexto: [INFORMACIÓN RELEVANTE]
   Prioridad: [CRITICAL/HIGH/MEDIUM/LOW]
   Output esperado: [QUÉ NECESITAS]"
```

---

## CONFIGURACIÓN POR MODELO

Los agentes usan diferentes modelos según complejidad:

### Internal Skills (18)
| Agente | Modelo | Razón |
|--------|--------|-------|
| recon-agent | sonnet | Tareas estructuradas |
| injection-agent | sonnet | Payloads conocidos |
| xss-agent | sonnet | XSS & WAF bypass |
| waf-bypass-agent | sonnet | WAF detection |
| api-agent | sonnet | Discovery sistemático |
| cloud-agent | sonnet | Checks definidos |
| auth-agent | sonnet | Análisis de tokens |
| documentation-agent | sonnet | Generación de texto |
| **ai-security-agent** | **opus** | Prompt injection, LLM |
| mobile-security-agent | sonnet | iOS/Android |
| **advanced-web-agent** | **opus** | HTTP smuggling, cache |
| subdomain-takeover-agent | sonnet | Takeover detection |
| race-condition-agent | sonnet | Concurrency |
| recon-automation-agent | sonnet | Automation pipeline |
| 🆕 **soap-security-agent** | **sonnet** | WSDL, XXE, SOAP auth |
| 🆕 **service-enumeration-agent** | **sonnet** | Swagger, admin endpoints |
| 🆕 **error-disclosure-agent** | **sonnet** | Error enumeration |
| 🆕 **network-recon-agent** | **sonnet** | CIDR, IP scanning |
| 🆕 **exploitability-validator** | **sonnet** | Validación de vectores de ataque prácticos |

### External Agents (6)
| Agente | Modelo | Razón |
|--------|--------|-------|
| **penetration-tester** | **opus** | Creatividad en exploits |
| **security-auditor** | **opus** | Análisis profundo |
| api-security-audit | sonnet | Checklists definidos |
| backend-architect | sonnet | Análisis estructural |
| code-reviewer | sonnet | Review sistemático |
| python-pro | sonnet | Código idiomático |

---

## CHECKLIST DE INICIO

```markdown
## Pre-Assessment

- [ ] Todos los agentes disponibles en /agents/
- [ ] Skills disponibles en /skills/
- [ ] Orchestrators configurados en /orchestrators/
- [ ] Entorno Python activado
- [ ] Dependencias instaladas
- [ ] Target confirmado: santelmo.org
- [ ] Autorización verificada

## Durante Assessment

- [ ] Fase actual documentada
- [ ] Findings registrados en tiempo real
- [ ] Escalaciones ejecutadas
- [ ] Rate limits respetados
- [ ] Checkpoints guardados

## Post-Assessment

- [ ] Todas las fases completadas
- [ ] Findings clasificados por severidad
- [ ] PoCs validados y reproducibles
- [ ] Reportes generados
- [ ] Export para plataforma bug bounty
```

---

## PROMPT DE INICIO UNIFICADO

```
Sos el Unified Orchestrator v2.0 para bug bounty. Coordinás 24 agentes especializados:

INTERNAL SKILLS (18):
Core Agents:
- recon-agent: Reconocimiento DNS/subdominios
- injection-agent: SQLi, NoSQLi, SSTI, CMDi
- api-agent: REST, GraphQL, WebSocket
- cloud-agent: AWS, Alibaba, SSRF
- auth-agent: JWT, OAuth, sessions, IDOR
- documentation-agent: Reportes y logging

Advanced Agents:
- xss-agent: XSS, WAF bypass, encoding
- waf-bypass-agent: WAF detection & bypass
- ai-security-agent: Prompt injection, LLM (opus)
- mobile-security-agent: iOS/Android
- advanced-web-agent: HTTP smuggling, cache poison (opus)
- subdomain-takeover-agent: Takeover detection
- race-condition-agent: Concurrency attacks
- recon-automation-agent: Automation pipeline

🆕 NEW Specialized Agents (v2.0):
- soap-security-agent: WSDL, XXE, SOAP auth bypass
- service-enumeration-agent: Swagger discovery, admin endpoints
- error-disclosure-agent: Error-based enumeration, stack traces
- network-recon-agent: CIDR scanning, IP enumeration, AWS recon

EXTERNAL AGENTS (6):
- penetration-tester: Explotación (opus)
- security-auditor: Auditoría OWASP (opus)
- api-security-audit: Seguridad de APIs
- backend-architect: Arquitectura
- code-reviewer: Revisión de código
- python-pro: Scripts profesionales

TARGET: Under Armour Bug Bounty (Bugcrowd)
- Domains: apphouse, ourhouse, transfer, vpe-us, snc, snctest-s, snctest-c, supplier, vtxapp9p/q/d, vtxappd
- IPs: 204.29.196.0/23, AWS IPs (3.133.230.28, 3.19.172.158, etc.)

REGLAS: Solo READ-ONLY, rate limit 2 req/s, documentar todo

Ejecutá el assessment en 5 fases, delegando tareas al agente apropiado según
la matriz de responsabilidades. Priorizá hallazgos críticos.

Para targets con IPs:
1. Usar network-recon-agent para CIDR expansion
2. Usar service-enumeration-agent para descubrir APIs expuestas
3. Usar soap-security-agent para WSDL/SOAP testing
4. Usar error-disclosure-agent para enumeration via errores

Comenzá con Fase 1: Reconocimiento usando recon-agent + network-recon-agent + backend-architect.
```

---

## 🆕 NUEVOS FLUJOS DE TRABAJO (v2.0)

### Flujo: IP/Network Target Testing
```yaml
trigger: "IP address or CIDR range provided"
workflow:
  1. network-recon-agent:
      - Expand CIDR to individual IPs
      - Identify cloud provider (AWS, Azure, GCP)
      - Multi-port scan (80, 443, 8080, 8443, 9000)
      - Banner grabbing

  2. service-enumeration-agent:
      - Discover API documentation endpoints
      - Scan for admin/debug endpoints
      - Test unauthenticated access
      - Enumerate exposed services

  3. Based on findings:
      - If SOAP/WSDL found → soap-security-agent
      - If REST API found → api-agent
      - If admin endpoint → penetration-tester
      - If verbose errors → error-disclosure-agent
```

### Flujo: Error-Based Enumeration
```yaml
trigger: "Different error messages based on resource existence"
workflow:
  1. error-disclosure-agent:
      - Identify error patterns
      - Build enumeration wordlist
      - Test resource existence
      - Extract ONLY CONFIRMED valid resources

  2. anti-speculation-validation:  # 🚨 OBLIGATORIO
      - Count ONLY items with actual evidence (request/response)
      - PROHIBIDO: Asumir nombres como "secrets", "tokens", "keys" sin probar
      - PROHIBIDO: Escribir "45+ collections" si solo confirmaste 10
      - Cada item listado DEBE tener su request/response

  3. documentation-agent:
      - Document ONLY confirmed resources
      - Table format: | Resource | Request | Response | Status |
      - NO speculation about "what might be stored"

  4. Based on CONFIRMED findings:
      - Report count = exactly what was tested and confirmed
      - Severity based on DEMONSTRATED access, not assumed sensitivity
      - Example: "10 collections confirmed" (not "45+ including secrets")
```

### 🚨 LECCION APRENDIDA: UA-2026-011
```yaml
# Error que causó corrección:
original_claim: "45+ collections including secrets, tokens, keys, payments"
realidad: "Solo 10 collections confirmadas (default, main, users...)"
problema: "INFLACIÓN - claims sin evidencia = rechazo Bugcrowd"

# Corrección aplicada:
- P2 → P3 (sin data modification demostrada)
- CVSS 7.3 → 5.3 (sin Integrity impact probado)
- "45+" → "10 confirmed"
- Removed: secrets, tokens, keys, payments (NUNCA probados)

# Regla:
"Si no lo probaste con request/response, NO existe en el reporte"
```

### Flujo: SOAP/WSDL Testing
```yaml
trigger: "WSDL or SOAP endpoint discovered"
workflow:
  1. soap-security-agent:
      - Parse WSDL for operations
      - Test each operation without auth
      - Test XXE via SOAP body
      - Test WS-Security bypass

  2. injection-agent:
      - Test SOAP parameters for injection
      - Test XML injection

  3. Based on findings:
      - If XXE works → CRITICAL, cloud-agent for SSRF
      - If auth bypass → penetration-tester
      - Document all unauthenticated operations
```

---

## 🚨 REGLAS DE CALIDAD BUGCROWD - OBLIGATORIO

> **REGLA DE ORO: Si no tenés prueba, NO lo escribas como hecho.**

### Antes de Crear Cualquier Reporte

```yaml
validacion_obligatoria:
  # PROHIBIDO - Causa rechazo N/A
  frases_prohibidas:
    - "May contain"
    - "Could potentially"
    - "Likely stores"
    - "Worst case scenario"
    - "If an attacker were to"
    - "This could lead to"
    - "Possibly", "Probably", "Might"

  # REQUERIDO
  cada_claim_necesita:
    - Request HTTP exacto (curl o raw)
    - Response HTTP completo
    - Código de estado (200, 401, 403, etc.)
    - Evidencia visual si aplica

  # SEVERIDAD
  severidad_basada_en:
    - Impacto DEMOSTRADO (no teórico)
    - PoC funcional
    - Consecuencia real probada
```

### Checklist Pre-Submit

```markdown
## Antes de Enviar a Bugcrowd

### ❌ Buscar y Eliminar
- [ ] "may contain" → Eliminar o probar
- [ ] "could potentially" → Demostrar o eliminar
- [ ] "worst case" → No especular
- [ ] "attackers could" → Solo lo que TÚ probaste

### ✅ Verificar
- [ ] Cada hallazgo tiene request/response
- [ ] Severidad = impacto demostrado
- [ ] Enumeración: solo items confirmados
- [ ] No mezclar "posible" con "confirmado"

### 🎯 Impacto
- [ ] "Como atacante, YO PUDE [acción]"
- [ ] NO: "Como atacante, podría potencialmente..."
```

### Ejemplo de Corrección

**MALO (será rechazado):**
```
Collections discovered: secrets, tokens, keys, passwords
These may contain sensitive API keys and credentials.
```

**BUENO (será aceptado):**
```
Collections confirmed via error enumeration:
- default: Response "Version not found in collection 'default'"
- users: Response "Version not found in collection 'users'"
Total: 10 collections confirmed (see evidence below)
```

---

### 🆕 Flujo: Exploitability Validation (OBLIGATORIO para vulns teóricas)
```yaml
trigger: "Host Header Injection, CORS, Open Redirect, CSRF, Clickjacking detected"
workflow:
  1. ANTES de documentar:
      - Enviar a exploitability-validator
      - NO crear reporte hasta validación completa

  2. exploitability-validator ejecuta:
      - Tests específicos por tipo de vulnerabilidad
      - Verifica vectores prácticos (no solo curl)
      - Determina si es explotable desde browser

  3. Resultado:
      - Si EXPLOITABLE → documentation-agent con PoC real
      - Si NO_PRACTICAL_VECTOR → rejected-findings.md + DESCARTAR

ejemplo_real:
  finding: "UA-2026-004 Host Header Injection"
  tests:
    - cache_poisoning: "❌ Cache disabled (no-cache, no-store)"
    - x_forwarded_host: "❌ Ignored"
    - x_host: "❌ Ignored"
    - password_reset: "❌ SPA with AJAX"
  resultado: "NO_PRACTICAL_VECTOR → RECHAZADO por Bugcrowd"
  leccion: "Validar ANTES de reportar hubiera evitado el rechazo"
```

---

## 🚨 LECCIÓN UA-2026-008: CORS CON WILDCARD NO ES EXPLOTABLE

### Resumen del Rechazo

**Hallazgo reportado**: CORS misconfiguration en vpe-us.underarmour.com con `Access-Control-Allow-Origin: *`
**Resultado**: N/A (Not Applicable)
**Razón de Bugcrowd**: "We require a PoC that demonstrates the impact... identify an endpoint that returns sensitive data"

### Por Qué No Es Explotable

```
┌──────────────────────────────────────────────────────┐
│      CORS WILDCARD (*) = NO EXPLOTABLE              │
├──────────────────────────────────────────────────────┤
│                                                      │
│ 1. `ACAO: *` + `credentials: include` = BLOQUEADO   │
│    → Los navegadores rechazan esta combinación      │
│                                                      │
│ 2. JWT en localStorage = PROTEGIDO POR SOP          │
│    → Same-Origin Policy, no CORS                    │
│                                                      │
│ 3. Sin credenciales = Sin sesión de víctima         │
│    → No hay datos del usuario que robar             │
│                                                      │
└──────────────────────────────────────────────────────┘
```

### Matriz de Explotabilidad CORS

| Configuración | Explotable | Razón |
|---------------|------------|-------|
| `ACAO: *` | ❌ NO | Credentials bloqueados |
| `ACAO: *` + `ACAC: true` | ❌ NO | Rechazado por browser |
| `ACAO: https://evil.com` (refleja) | ⚠️ MAYBE | Solo si hay credentials |
| `ACAO: https://evil.com` + `ACAC: true` | ✅ SÍ | Explotable completo |
| `ACAO: null` + `ACAC: true` | ✅ SÍ | Via iframe sandboxed |

### Workflow CORS Actualizado

```yaml
cors_testing_workflow:
  step_1_check_reflection:
    command: |
      curl -sI "https://target/api/" -H "Origin: https://evil.com" | grep -i "access-control"
    decision:
      - if: "ACAO: *" → STOP, no explotable
      - if: "ACAO: https://evil.com" → Continuar

  step_2_check_credentials:
    command: |
      # Buscar Access-Control-Allow-Credentials: true
    decision:
      - if: "No ACAC header" → STOP, no explotable sin cookies
      - if: "ACAC: true" → Continuar

  step_3_check_auth_method:
    analysis:
      - Cookie-based auth → Continuar
      - JWT localStorage → STOP, SOP protege
      - Bearer header → STOP, attacker no puede leer

  step_4_check_sensitive_endpoint:
    requirement: "Endpoint que retorna datos del USUARIO, no públicos"
    decision:
      - if: "Solo data pública" → STOP
      - if: "User-specific data" → Continuar a PoC

  step_5_only_if_all_pass:
    action: "Crear PoC HTML con fetch + credentials: include"
    output: "cors-poc.html que roba datos del usuario"

  # REGLA CRÍTICA
  any_step_fails: "NO REPORTAR - cerrar como N/A interno"
```

### Actualización al Flujo de Vulnerabilidades

```yaml
# ANTES (incorrecto)
vulnerabilidades_a_validar:
  - Host Header Injection → exploitability-validator
  - Open Redirect → exploitability-validator
  - CSRF → exploitability-validator

# AHORA (correcto - incluye CORS)
vulnerabilidades_que_requieren_validacion_especial:
  - Host Header Injection → exploitability-validator (cache, X-Forwarded-Host)
  - CORS Misconfiguration → exploitability-validator (reflection, credentials, auth type)
  - Open Redirect → exploitability-validator (automático, OAuth chain)
  - CSRF → exploitability-validator (SameSite, cookies)
  - Clickjacking → exploitability-validator (acciones sensibles)
```

---

**Versión**: 2.4
**Agentes Totales**: 25 (19 skills + 6 agents)
**Orchestrators**: 4 (main, owasp, api, unified)
**Changelog**:
- v2.4 (2026-01-30): **Lección CORS UA-2026-008** - wildcard no explotable, workflow CORS actualizado
- v2.3 (2026-01-30): Anti-speculation validation en Error Enumeration workflow, Lección UA-2026-011 documentada
- v2.2 (2026-01-30): exploitability-validator agent, Fase 4.5 de validación, Flujo de exploitability
- v2.1 (2026-01-30): Reglas de calidad Bugcrowd, Checklist pre-submit, Validación obligatoria
- v2.0 (2026-01-29): soap-security-agent, service-enumeration-agent, error-disclosure-agent, network-recon-agent
