***
name: web-bugbounty-elite
description: |
  Professional-grade web application penetration testing and bug bounty hunting 
  methodology. Covers passive/active reconnaissance, API discovery, vulnerability 
  chaining (SQLi→RCE, SSRF→RCE, IDOR→Account Takeover), WAF bypass, CORS abuse, 
  and submission-ready reporting. Integrates with elite recon MCPs for $100k+ findings.
version: 1.0.0
author: Web Security Research Team
domain: web-application-security
difficulty: expert
prerequisites:
  - Burp Suite Professional
  - Subfinder, Amass, PureDNS
  - FFUF, SQLMap, Nuclei
  - GitHub Personal Access Token
mcp_integrations:
  - elite-recon-mcp
  - bugbounty-gokul
  - web-pentesting-mcp
***

# Web Pentesting & Bug Bounty Élite

## 1. FASE DE RECONOCIMIENTO PASIVO PROFUNDO

### 1.1 Enumeración de Subdominios y Dominios Relacionados

**Objetivo:** Crear inventario completo de activos expuestos sin interactuar directamente con el target.

**Metodología con MCP:**
1. **Subdomain Discovery**: Usar `elite-recon-mcp` con herramienta `subdomain_enum` combinando subfinder, amass, y permutaciones
2. **CNAME Chain Analysis**: Ejecutar `cname_chain_analysis` para identificar servicios de terceros y takeover opportunities
3. **DNS Entropy Scanning**: Detectar subdominios generados dinámicamente posibles para exfiltración

**Prompts de Ejemplo:**

"Usa elite-recon-mcp para enumerar subdominios de target.com usando técnicas pasivas y activas"

### 1.2 Análisis de Infraestructura Cloud

**Objetivo:** Mapear servicios cloud (AWS, GCP, Azure, Fastly, Cloudflare) y buckets expuestos.

**Procedimiento:**
- Ejecutar `cloud_infrastructure_mapper` desde `elite-recon-mcp`
- Identificar S3/GCS buckets con permisos públicos
- Analizar CloudFront distributions y Lambda@Edge

**Checklist de Vulnerabilidades:**
- S3 buckets públicos con listable content
- Firebase databases sin autenticación
- Azure blob storage con anonymous access
- Cloud Functions con triggers HTTP públicos

### 1.3 Extracción de Secrets en JavaScript

**Objetivo:** Encontrar API keys, tokens, endpoints internos, y lógica de negocio en client-side code.

**Técnicas:**
- **Source Map Mining**: Descargar .js.map files y analizar estructura completa
- **Dynamic Endpoint Discovery**: Ejecutar `javascript_secret_extractor` para extraer:
  - API endpoints (`/api/v1/admin`, `/internal/debug`)
  - AWS/GCP keys
  - JWT secrets
  - GraphQL endpoints

**Prompts:**

"Usa elite-recon-mcp para extraer todos los secrets y endpoints de https://target.com"

***

## 2. FASE DE RECONOCIMIENTO ACTIVO INTELIGENTE

### 2.1 Fuzzing de Endpoints y Parámetros

**Objetivo:** Descubrir endpoints ocultos, parámetros vulnerables, y funcionalidades no documentadas.

**Metodología:**
1. **Parameter Discovery**: Usar ParamSpider, Arjun, y ffuf con wordlists custom
2. **Content Discovery**: FFUF con múltiples wordlists (common.txt, api.txt, backup.txt)
3. **API Version Fuzzing**: Probar /v1/, /v2/, /beta/, /internal/

**Rate Limiting y Evasión:**
- Distribuir requests entre múltiples IPs (proxies)
- Usar delays aleatorios (0.5-2 segundos)
- Rotar User-Agents con cada request

### 2.2 Análisis de WAF y Técnicas de Bypass

**Objetivo:** Identificar WAF y desarrollar payloads específicos de evasión.

**Procedimiento:**
1. **WAF Fingerprinting**: Usar `wafw00f` y `nmap http-waf-fingerprint`
2. **Parse Error Detection**: Enviar payloads malformados para ver comportamiento
3. **Normalization Bypass**: Usar diferentes codificaciones (URL, double URL, Unicode)

**Técnicas de Bypass Comunes:**
- **CL.TE**: Content-Length vs Transfer-Encoding discrepancies
- **Parameter Pollution**: `id=1&id=2` para bypass de validación
- **HTTP/2 Downgrade**: Convertir requests a HTTP/1.1 para evitar reglas

***

## 3. FASE DE VULNERABILITY CHAINS ÉLITE

### 3.1 SQL Injection → Remote Code Execution

**Objetivo:** Escalar SQLi a shell interactiva o RCE.

**Cadenas de Ataque:**
1. **OOB SQLi**: Usar DNS exfiltration para data extraction
2. **Second-Order SQLi**: Inyectar en un endpoint, explotar en otro
3. **Stacked Queries**: `; EXEC xp_cmdshell` (MSSQL) o `SELECT ... INTO OUTFILE` (MySQL)

**Prompts de Explotación:**
"Genera payloads políglotas para probar SQLi en parámetros JSON y headers"

### 3.2 SSRF → Internal Network Compromise

**Objetivo:** Usar el servidor web como proxy para atacar la red interna.

1. **Cloud Metadata**: `http://169.254.169.254/latest/meta-data/` (AWS)
2. **Internal Port Scan**: Escanear localhost y rangos privados (10.0.0.0/8)
3. **Protocol Smuggling**: Usar `gopher://` para hablar con Redis o SMTP interno.

### 3.3 IDOR → Account Takeover (ATO)

**Objetivo:** Comprometer cuentas de otros usuarios mediante manipulación de IDs.

1. **HPP (HTTP Parameter Pollution)**: Enviar `id=VICTIM&id=ATTACKER`.
2. **JSON Type Confusion**: Enviar ID como integer en vez de string.
3. **API Leaks**: Buscar endpoints que devuelvan PII excesivo en respuestas.

***

## 4. REPORTING Y TRIAGE

**Estructura de Reporte Ganador:**
1. **Título Claro**: `[Critical] RCE via Unauthenticated File Upload`
2. **Impacto de Negocio**: Explicar pérdida financiera/datos, no solo técnica.
3. **Pasos de Reproducción**: Comandos `curl` exactos.
4. **PoC**: Video o script corto demostrando el fallo.

**Nota:** Siempre reportar cadenas completas (Chain) en lugar de fallos aislados para maximizar el bounty.
