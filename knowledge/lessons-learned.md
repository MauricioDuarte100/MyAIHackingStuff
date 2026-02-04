# Lessons Learned - Bug Bounty Knowledge Base (Nubank Brasil)

Este archivo contiene todas las lecciones aprendidas durante assessments de bug bounty.
Antigravity Code carga este archivo automaticamente desde `.antigravity/knowledge/`.

---

## PROGRAMA ACTUAL: Nubank Brasil

**Plataforma**: Bugcrowd
**Inicio Assessment**: 2026-01-30
**Status**: Iniciando

---

## LECCIONES DE ASSESSMENTS ANTERIORES (Referencia)

Las siguientes lecciones fueron aprendidas en assessments previos y aplican universalmente:

### LECCION UNIVERSAL 1: Supply Chain CVE - Detectado != Vulnerable

**Regla**:
> - package.json NO es evidencia suficiente
> - Verificar codigo en PRODUCCION bundle
> - Tree-shaking elimina dependencias no usadas

### LECCION UNIVERSAL 2: CORS Wildcard NO es Explotable

**Regla**:
> CORS es explotable SOLO si:
> 1. Origin es REFLEJADO (no wildcard)
> 2. Access-Control-Allow-Credentials: true
> 3. Auth es via COOKIES (no localStorage JWT)
> 4. Endpoint tiene datos sensibles

### LECCION UNIVERSAL 3: Host Header Injection Requiere Vector Practico

**Regla**:
> curl con Host header modificado != ataque real
> El browser SIEMPRE controla el Host header
> Solo explotable via cache poisoning o X-Forwarded-*

### LECCION UNIVERSAL 4: Enumeracion - Claims = Evidencia

**Regla**:
> Numero reportado = Numero de evidencias
> NO usar "N+" si no probaste N
> NO llamar items "CRITICAL" sin probarlos

### LECCION UNIVERSAL 5: Frases Prohibidas en Reportes

**NUNCA usar**:
- "May contain..."
- "Could potentially..."
- "Likely stores..."
- "Attackers could theoretically..."

**SI usar**:
- "Confirmed X items with evidence"
- "Successfully accessed..."
- "Server returned..."

---

## VALIDADORES OBLIGATORIOS

| Tipo de Vulnerabilidad | Validador | Si falla |
|------------------------|-----------|----------|
| Host Header, CORS, CSRF | exploitability-validator | NO REPORTAR |
| CVE en dependencia | supply-chain-agent | NO REPORTAR |
| Subdomain Takeover | N/A | NO REPORTAR (no reward en Nubank) |
| LLM/AI vulns | N/A | NO REPORTAR (temporalmente OOS) |
| Open Redirect | Demostrar impacto adicional | NO REPORTAR sin impacto |
| Enumeracion | Verificar N items = N evidencias | Ajustar numero |

---

## WORKFLOW PRE-REPORTE

```
1. DISCOVERY
   └── Encontrar vulnerabilidad potencial

2. CLASSIFICATION
   ├── Subdomain takeover → NO REPORTAR (Nubank)
   ├── LLM/AI → NO REPORTAR (temporal)
   ├── Host/CORS/Redirect → exploitability-validator
   ├── CVE dependency → supply-chain-agent
   └── Enumeration → count = evidence

3. VALIDATION
   └── Ejecutar validador apropiado
       └── Si FAIL → NO REPORTAR

4. EVIDENCE
   └── Capturar request/response con X-Correlation-Id

5. IMPACT
   └── Describir lo que REALMENTE hiciste

6. REPORT
   └── Solo hechos confirmados
   └── Incluir header X-Correlation-Id
   └── PoC max R$ 10 para transacciones
```

---

## LECCIONES NUBANK (Assessment Actual)

*Las lecciones se agregaran automaticamente a medida que se descubran durante este assessment.*

---

**Version**: 1.0 (Nubank Brasil)
**Iniciado**: 2026-01-30
