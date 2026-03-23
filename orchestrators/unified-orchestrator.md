# 🎯 ANTIGRAVITY UNIFIED ORCHESTRATOR v3.0
## Orquestación Suprema de +100 Skills para Full-Stack Security Assessment

Este orquestador coordina todas las capacidades de Antigravity para ejecutar ataques complejos y auditorías profesionales.

---

## 🧠 EL CEREBRO DEL ASSESSMENT

El orquestador utiliza la herramienta `activate_skill` para cargar dinámicamente las capacidades necesarias según la fase y el target.

### Matriz de Skills por Especialidad

| Categoría | Skills Clave (Cargar con activate_skill) |
|-----------|------------------------------------------|
| **Pwn & Kernel** | `ctf-pwn`, `linux-pentesting-elite`, `windows-mitigations`, `shellcode` |
| **Reversing** | `ctf-reverse`, `dwarf-expert`, `binary-analysis`, `pe-and-dotnet` |
| **Web Offense** | `xss-agent`, `sqli`, `idor`, `jwt-attacks`, `oauth-attacks`, `ssrf`, `ssti` |
| **Infrastructure**| `ad-pentesting-elite`, `cloud-native-ad-specialist`, `network-recon-agent` |
| **Malware** | `ctf-malware`, `yara-rule-authoring`, `webshell-detection-expert`, `edr-evasion`|
| **Crypto** | `ctf-crypto`, `constant-time-analysis`, `wycheproof` |
| **Auditoría** | `solidity-auditor`, `semgrep`, `zeroize-audit`, `variant-analysis` |

---

## 🚀 WORKFLOW OPERATIVO SUPREMO

### Fase 1: Reconocimiento & Superficie de Ataque
1. Activar `recon-agent` para descubrimiento de subdominios y tech stack.
2. Activar `network-recon-agent` para escaneo de puertos y expansión de IPs.
3. Activar `service-enumeration-agent` para localizar APIs, Swagger y WSDL.

### Fase 2: Análisis de Vulnerabilidades (Mapping)
1. Activar `api-agent` para mapear REST/GraphQL.
2. Activar `soap-security-agent` si se detectan servicios XML.
3. Activar `error-disclosure-agent` para extraer información de stack traces.

### Fase 3: Explotación Dirigida
- **Si es Web:** Activar `injection-agent`, `xss-agent`, `waf-bypass-agent`.
- **Si es Binario:** Activar `ctf-pwn`, `ctf-reverse`.
- **Si es AD/Windows:** Activar `ad-pentesting-elite`, `advanced-kerberos-master`.
- **Si es Cloud:** Activar `cloud-agent`.

### Fase 4: Evasión & Post-Explotación
1. Activar `edr-evasion` para bypass de seguridad en el host.
2. Activar `stealth-evasion-specialist` para ocultar actividad de SIEM/SOC.
3. Activar `privilege-escalation` (Linux/Windows según corresponda).

### Fase 5: Validación & Reporte Profesional
1. Activar `exploitability-validator` para descartar falsos positivos.
2. Activar `documentation-agent` para generar el reporte final en formato Bug Bounty.

---

## 🚨 REGLAS DE ORO DE ANTIGRAVITY

1. **Eficiencia en Contexto:** No leas archivos innecesarios. Usa `grep_search` y `glob` en paralelo.
2. **Mentalidad Adversaria:** Cuestiona siempre el "403 Forbidden". Intenta bypasses con `waf-bypass-agent`.
3. **Evidencia Irrefutable:** Cada hallazgo DEBE tener una request/response que lo pruebe.
4. **Impacto de Negocio:** No reportes bugs, reporta riesgos empresariales.

---

## 🛠️ COMANDO DE INICIO UNIFICADO

Para iniciar un assessment completo, usa:
```bash
antigravity --config orchestrators/unified-orchestrator.md "Iniciar Full Assessment contra [TARGET]"
```

Para activar una skill específica en cualquier momento:
```javascript
activate_skill({name: "nombre-de-la-skill"})
```
