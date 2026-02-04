# Scope Rules - Nubank Brasil Bug Bounty

Este archivo define el scope del programa.

---

## REGLA CRITICA

> **Testing is only authorized on the targets listed as in scope.**
> **Any domain/property NOT listed is OUT OF SCOPE.**
> **This includes any/all subdomains not explicitly listed.**

---

## Targets IN-SCOPE

### Primary Assets - Wildcards
| Target | Tags | Known Issues | Rewards |
|--------|------|--------------|---------|
| *.nubank.com.br | Wildcard, Brasil | 12 | P1: $1000-$2000, P2: $600-$1000, P3: $300-$400, P4: $50-$100 |
| *.nu.com.mx | Wildcard, Mexico | 5 | P1: $1000-$2000, P2: $600-$1000, P3: $300-$400, P4: $50-$100 |
| *.nu.com.co | Wildcard, Colombia | 6 | P1: $1000-$2000, P2: $600-$1000, P3: $300-$400, P4: $50-$100 |

### Supplementary Assets
| Target | Tags | Known Issues | Rewards |
|--------|------|--------------|---------|
| *.nuinvest.com.br | Website Testing | 7 | P1: $500-$1000, P2: $300-$500, P3: $150-$300, P4: $50-$100 |

### Mobile Applications
| Target | Platform | Store |
|--------|----------|-------|
| Nubank iOS | iOS | App Store |
| Nubank Android | Android | Play Store |

### Core Assets - PROMOCION FEBRERO (2x Rewards)
| Target | Rewards PROMO |
|--------|---------------|
| prod-*.nubank.com.br | P1: $4000-$8000, P2: $2000-$4000 |
| prod-*.nubank.com.mx | P1: $4000-$8000, P2: $2000-$4000 |
| prod-*.nubank.com.co | P1: $4000-$8000, P2: $2000-$4000 |
| Nubank iOS App | P1: $4000-$8000, P2: $2000-$4000 |
| Nubank Android App | P1: $4000-$8000, P2: $2000-$4000 |

> **Promocion activa**: Feb 1-28, 2026 (o hasta agotar presupuesto)

---

## Targets OUT-OF-SCOPE

### Dominios Excluidos
- *.nuinternational.com
- *.nat-a.nubank.com.br
- international.nubank.com.br
- NuCommunity endpoints (BR, MX, CO) - temporalmente fuera por mantenimiento

---

## Vulnerabilidades OUT-OF-SCOPE

### NO Reportar (sin reward)
- **Subdomain takeover reports** - NO eligible for reward
- **LLM Based Applications** - temporalmente out of scope
- Social engineering (phishing, vishing, smishing) - PROHIBIDO
- Credential leakages from end users (no causadas por falla de Nubank)

### Requieren Impacto Adicional
- Open redirect - **solo con impacto de seguridad adicional demostrable**
- Content spoofing - **solo con modificacion de HTML/CSS**
- CSV injection - **solo con vulnerabilidad demostrada**

### Best Practices (NO reportar)
- Missing best practices in SSL/TLS configuration
- Missing best practices in CSP
- Missing HttpOnly or Secure flags on cookies
- Missing email best practices (SPF/DKIM/DMARC)
- Software version disclosure / Banner identification
- Descriptive error messages or headers (stack traces)

### Contexto Limitado (NO reportar)
- Clickjacking on pages with no sensitive actions
- CSRF on unauthenticated forms or forms with no sensitive actions
- Attacks requiring MITM or physical access
- Previously known vulnerable libraries without working PoC
- Vulnerabilities affecting outdated browsers (<2 stable versions)
- Issues that require unlikely user interaction
- Tabnabbing

### Rate Limiting
- **SOLO reportar** rate limiting en endpoints de **autenticacion**
- Rate limiting en otros endpoints es OUT OF SCOPE

### Otros
- NuInvest's Hijacked Social Media
- Availability attacks, DOS, or DDoS

---

## Acciones PERMITIDAS

- Reconocimiento pasivo y activo
- Enumeracion de endpoints, parametros, APIs
- Testing de apps moviles (iOS/Android)
- Explotacion (solo lectura de datos)
- Bypass de auth (sin modificar datos)
- SQL Injection (SELECT only - NUNCA DELETE/UPDATE/DROP)
- XSS (solo PoC)
- SSRF para lectura de metadata
- IDOR para acceso a datos
- Rate limiting bypass en endpoints de AUTH
- Crear cuenta de test (solo investigadores brasileos con CPF)

---

## Acciones PROHIBIDAS

- Availability attacks, DOS, DDoS
- Social engineering (phishing, vishing, smishing)
- Uso de identificacion falsa o fraude
- Eliminacion o modificacion de datos
- Ataques a usuarios reales
- Acceso a sistemas fuera de scope
- Exfiltracion masiva de PII
- Cualquier accion destructiva
- Empleados de Nubank/Third Party Providers NO pueden participar

---

## Headers OBLIGATORIOS

```http
X-Correlation-Id: bc-handle
```

> **IMPORTANTE**: Usar en TODAS las requests para identificar actividad autorizada

---

## Limites de PoC

```yaml
max_value: "R$ 10"
currency: "BRL"
note: "Usar el minimo posible para tests con transacciones"
```

---

## Rewards Primary Assets

| Severity | Normal | PROMO (Feb) |
|----------|--------|-------------|
| P1 | $1,000 - $2,000 | $4,000 - $8,000 |
| P2 | $600 - $1,000 | $2,000 - $4,000 |
| P3 | $300 - $400 | $300 - $400 |
| P4 | $50 - $100 | $50 - $100 |

## Rewards Supplementary (NuInvest)

| Severity | Reward |
|----------|--------|
| P1 | $500 - $1,000 |
| P2 | $300 - $500 |
| P3 | $150 - $300 |
| P4 | $50 - $100 |

---

## SLAs de Respuesta

| Metrica | Target |
|---------|--------|
| First Response | 2 dias |
| Time to Triage | 2 dias |
| Time to Resolution | Depende de severidad y complejidad |

---

## Acceso con Cuenta de Test (Solo Brasil)

Para investigadores brasileos con CPF:
1. Descargar app de Play Store o App Store
2. Ser mayor de 18 anos
3. Tener CPF registrado
4. Dispositivo compatible con version actual
5. Proveer info personal incluyendo foto de RG

> **Si cuenta bloqueada por fraude**: Notificar inmediatamente con detalles de tests

---

## Reglas de Duplicados

- Solo el **primer reporte** es triaged (si es reproducible)
- Multiples vulnerabilidades del mismo issue = 1 reporte valido
- 1 vulnerabilidad por reporte

---

## Quality Reporting

Incluir en cada reporte:
1. **Pasos detallados** de replicacion (paso a paso)
2. **Escenario de exploit real** (no hipotetico extremo)
3. **Remediacion ACTIONABLE** (no generica)

> Submissions sin pasos de explotacion detallados NO son elegibles para reward

---

**Version**: 4.0 (Nubank Brasil)
**Actualizado**: 2026-01-30
