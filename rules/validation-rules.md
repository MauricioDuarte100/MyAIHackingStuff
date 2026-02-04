# Validation Rules - Pre-Report Checklist (Nubank Brasil)

Este archivo define las reglas de validacion OBLIGATORIAS antes de reportar.

---

## REGLA GENERAL

> **Si no podes decir "Como atacante, YO PUDE [accion]", NO es reportable**

---

## REGLAS ESPECIFICAS NUBANK

### Header Obligatorio
```http
X-Correlation-Id: bc-handle
```
> Incluir en TODAS las requests - identifica actividad autorizada

### Limite de PoC (Transacciones)
```yaml
max_value: "R$ 10"
currency: "BRL"
note: "Usar el minimo posible para tests con transacciones"
```

### NO Reportar en Nubank
- **Subdomain takeover** - NO eligible for reward
- **LLM/AI Applications** - temporalmente out of scope
- **Rate limiting** en endpoints NO de autenticacion
- **Open redirect** sin impacto adicional demostrable

---

## Validador: Supply Chain CVE

**Trigger**: Cuando encuentres CVE en dependencia

### Checklist OBLIGATORIO
- [ ] Codigo en bundle de PRODUCCION (grep library-name bundle.js)
- [ ] Funcion vulnerable es llamada
- [ ] Input controlable por atacante
- [ ] Resultado afecta decision de seguridad
- [ ] PoC funcional

### Comandos
```bash
# Descargar bundle
curl -sL "https://target.com/bundle.js" > /tmp/bundle.js

# Buscar libreria
grep -i "library-name" /tmp/bundle.js | wc -l

# Si 0 matches -> STOP - NO REPORTAR
```

### Agente: supply-chain-agent

---

## Validador: Host Header / CORS / CSRF

**Trigger**: Vulnerabilidades que dependen de comportamiento del browser

### Host Header Injection
- [ ] X-Forwarded-Host funciona?
- [ ] Hay caching habilitado?
- [ ] Password reset usa Host header?
- [ ] PoC funciona desde BROWSER?

### CORS Misconfiguration
- [ ] Origin es REFLEJADO? (no wildcard *)
- [ ] Access-Control-Allow-Credentials: true?
- [ ] Auth via cookies? (no localStorage JWT)
- [ ] Datos sensibles en respuesta?

### CSRF
- [ ] SameSite cookies?
- [ ] CSRF token presente?
- [ ] Auth via cookies?
- [ ] Accion sensible?

### Agente: exploitability-validator

---

## Validador: Enumeracion

**Trigger**: Cuando reportes N items descubiertos

### Checklist
- [ ] N items reportados = N evidencias con request/response
- [ ] NO usar "N+" sin probar todos
- [ ] NO llamar items "CRITICAL" sin verificar contenido
- [ ] CVSS I:N si no demostras modificacion

---

## Validador: Info Disclosure

**Trigger**: Cuando reportes exposicion de informacion

### Checklist
- [ ] Datos son realmente sensibles?
- [ ] No es informacion publica por diseno?
- [ ] Hay impacto de seguridad demostrable?

---

## Frases PROHIBIDAS

Nunca usar en reportes:
- "May contain..."
- "Could potentially..."
- "Likely stores..."
- "Suggests that..."
- "Worst case scenario..."
- "If an attacker were to..."
- "Attackers could theoretically..."
- "N+ items discovered" (sin evidencia)

---

## Workflow

```
DISCOVERY → CLASSIFICATION → VALIDATION → EVIDENCE → IMPACT → REPORT
                                ↓
                         Si falla → NO REPORTAR
```
