# OWASP Top 10 2025 (8va Edicion)

Este archivo define las categorias OWASP 2025 y como testearlas.

---

## Cambios vs 2021

| # | Categoria 2025 | Cambio vs 2021 | Agente |
|---|----------------|----------------|--------|
| A01 | Broken Access Control | SSRF incluido aqui | auth-agent |
| A02 | Security Misconfiguration | Subio de #5 a #2 | service-enumeration-agent |
| **A03** | **Software Supply Chain** | **NUEVA** | supply-chain-agent |
| A04 | Cryptographic Failures | Bajo de #2 a #4 | security-auditor |
| A05 | Injection | Bajo de #3 a #5 | injection-agent |
| A06 | Insecure Design | Bajo de #4 a #6 | backend-architect |
| A07 | Authentication Failures | Se mantiene | auth-agent |
| A08 | Integrity Failures | Se mantiene | security-auditor |
| A09 | Logging Failures | Se mantiene | error-disclosure-agent |
| **A10** | **Exception Handling** | **NUEVA** | error-disclosure-agent |

---

## A03:2025 - Software Supply Chain Failures (NUEVA)

### Descripcion
- Mayor promedio de exploit e impact scores
- Incluye dependencias vulnerables
- Ataques a la cadena de suministro

### Testing Obligatorio
1. Verificar codigo en bundle de PRODUCCION
2. Confirmar que funcion vulnerable es llamada
3. Validar que input es controlable
4. Demostrar impacto con PoC

### Validador: supply-chain-agent
```bash
grep -i "library-name" bundle.js | wc -l
# Si 0 -> NO REPORTAR
```

---

## A10:2025 - Mishandling of Exceptional Conditions (NUEVA)

### Descripcion
- Errores que revelan informacion
- Auth que falla abierto (CWE-636)
- Excepciones no manejadas

### Testing
1. Enviar inputs malformados
2. Observar mensajes de error
3. Buscar stack traces
4. Verificar que auth no falle open

### Agente: error-disclosure-agent

---

## Metodologia por Categoria

### A01: Broken Access Control
- IDOR testing
- Privilege escalation
- SSRF (ahora incluido aqui)
- Path traversal

### A02: Security Misconfiguration
- Debug endpoints expuestos
- Headers de seguridad faltantes
- Config files accesibles
- Admin panels sin auth

### A03: Supply Chain
- Bundle analysis
- CVE validation en produccion
- Dependency tree review

### A04: Cryptographic Failures
- TLS configuration
- Weak algorithms
- Key management

### A05: Injection
- SQLi (ORMs lo mitigan)
- NoSQLi
- Command injection
- XXE (raro en 2026)

### A06: Insecure Design
- Business logic flaws
- Rate limiting
- Trust boundaries

### A07: Authentication Failures
- Brute force
- Session management
- JWT vulnerabilities

### A08: Integrity Failures
- Code/data tampering
- Insecure deserialization
- Missing SRI

### A09: Logging Failures
- Insufficient logging
- Log injection
- Missing audit trails

### A10: Exception Handling
- Error disclosure
- Fail-open auth
- Verbose errors

---

**Referencia**: https://owasp.org/Top10/2025/
