# Writeups Integration Rules

Este archivo define como los agentes deben consultar y aprender de los writeups almacenados en `.antigravity/writeups/`.

---

## REGLA PRINCIPAL

> **TODOS los agentes DEBEN consultar los writeups cuando:**
> 1. Encuentran una tecnologia o vulnerabilidad similar
> 2. Necesitan payloads o tecnicas especificas
> 3. Quieren validar un approach antes de ejecutarlo
> 4. Buscan referencias de explotacion exitosa

---

## Ubicacion de Writeups

```
.antigravity/writeups/
├── 23 CTF directories (0x41414141, cyber_apocalypse, DiceCTF, etc.)
├── 85+ standalone writeups
└── Total: 181 writeups
```

---

## CTFs Organizados (23 directorios)

| CTF | Cantidad | Categorias Principales |
|-----|----------|------------------------|
| 0x41414141 | 15+ | Web, Blockchain, Crypto, Misc, Reversing |
| cyber_apocalypse | 20+ | Web, Crypto, Hardware, Misc |
| DiceCTF | 6 | Web (CSP bypass), Reversing |
| SharkyCTF-2020 | 6 | XXE, Auth bypass, Web |
| VolgaCTF-2020 | 3 | SQLi, LFI, Web |
| CodeGate-2020 | 2 | CSP bypass, SSRF |
| Web Security ACADEMY | 5 | Clickjacking (todos) |
| CTFZone-Quals-2019 | 3 | Web challenges |
| NahamCONCTF-2020 | 2 | Web |
| Seccon-Quals-2019 | 3 | Web, Crypto |
| + 13 CTFs mas | Various | Mixed |

---

## Categorias de Writeups

### API Security (PRIORIDAD ALTA)
- WRITEUP_graphql.md - Introspection, BOLA, IDOR, Batching
- WRITEUP_apivault.md - JWT, SSRF, Race Condition, Mass Assignment
- 0x41414141/web/graphed_2 - GraphQL IDOR
- cyber_apocalypse/web/* - 11 web challenges

### Web Vulnerabilities
- cyber_apocalypse/web/blitzprop - Prototype Pollution
- cyber_apocalypse/web/caas - Command Injection
- cyber_apocalypse/web/wild_goose_hunt - NoSQL Injection
- SharkyCTF-2020/web-xxexternalxx - XXE OOB
- DiceCTF/web/babier_csp - CSP Bypass
- JustCTF-2019/web-cache-review - Cache Poisoning
- CodeGate-2020/web-renderer - SSRF

### Cloud/Container
- CTF_Writeup_Kubernetes.md - K8s privilege escalation
- MediCloudX_*.md - Cloud security series (5 writeups)

### Blockchain (NUEVO)
- 0x41414141/blockchain/* - Smart contracts, Solidity
- crypto_casino, secure_enclave, crackme

### Hardware (NUEVO)
- cyber_apocalypse/hardware/* - Serial logs, I2C, SPI analysis

### Crypto
- WRITEUP-padding_oracle.md - CBC padding oracle
- cyber_apocalypse/crypto/* - XOR, Stream ciphers
- 0x41414141/crypto/factorize - RSA

### Binary/PWN
- writeup_exploit.md, writeup_pwnfeelmyterror.md
- WRITEUP_ret3syscall.md - ROP chains
- 0x41414141/reversing/* - Static analysis

### Forensics
- writeup_forense.md - Memory/disk analysis
- writeup_malware_downlaod.md

### Clickjacking (Web Security Academy)
- Basic clickjacking attack.md
- Clickjacking with prefilled form input.md
- Combining clickjacking with DOM XSS.md
- Frame busting scripts.md
- Multistep clickjacking.md

---

## Cuando Consultar Writeups

### Trigger: Tecnologia Detectada

| Tecnologia | Writeup(s) a Consultar |
|------------|------------------------|
| GraphQL | WRITEUP_graphql.md, 0x41414141/web/graphed_2 |
| Kubernetes/Docker | CTF_Writeup_Kubernetes.md |
| JWT | WRITEUP_apivault.md (FLAG 1) |
| API REST | WRITEUP_apivault.md, cyber_apocalypse/web/* |
| OAuth | WRITEUP_apivault.md (FLAG 9) |
| SOAP/XML/XXE | SharkyCTF-2020/web-xxexternalxx |
| Serialization | WRITEUP_apivault.md (FLAG 10), cyber_apocalypse/web/daas |
| CSP | DiceCTF/web/babier_csp, CodeGate-2020/web-csp |
| Blockchain/Smart Contracts | 0x41414141/blockchain/* |
| Hardware/Embedded | cyber_apocalypse/hardware/* |

### Trigger: Vulnerabilidad Sospechada

| Vulnerabilidad | Writeup(s) a Consultar |
|----------------|------------------------|
| IDOR/BOLA | WRITEUP_graphql.md, WRITEUP_apivault.md, 0x41414141/web/graphed_2 |
| Race Condition | WRITEUP_apivault.md (FLAG 3) |
| SSRF | WRITEUP_apivault.md (FLAG 4), CodeGate-2020/web-renderer |
| Cache Poisoning | WRITEUP_apivault.md (FLAG 5), JustCTF-2019/web-cache-review |
| Prototype Pollution | WRITEUP_apivault.md (FLAG 6), cyber_apocalypse/web/blitzprop |
| Timing Attack | WRITEUP_apivault.md (FLAG 7) |
| Mass Assignment | WRITEUP_apivault.md (FLAG 8) |
| Introspection | WRITEUP_graphql.md (FLAG 2) |
| Command Injection | cyber_apocalypse/web/caas |
| NoSQL Injection | cyber_apocalypse/web/wild_goose_hunt |
| Clickjacking | Web Security ACADEMY/* (5 writeups) |
| XXE | SharkyCTF-2020/web-xxexternalxx |
| CSP Bypass | DiceCTF/web/babier_csp, CodeGate-2020/web-csp |
| SSTI | GACTF-2020/web-simpleflask |

---

## Formato de Consulta

### Busqueda por Tecnica
```bash
# Buscar en writeups por palabra clave
grep -r "SSRF\|ssrf" .antigravity/writeups/ --include="*.md"
grep -r "GraphQL\|graphql" .antigravity/writeups/ --include="*.md"
grep -r "JWT\|jwt" .antigravity/writeups/ --include="*.md"
```

### Extraccion de Payloads
```bash
# Extraer bloques de codigo curl
grep -A 10 "```bash" .antigravity/writeups/WRITEUP_graphql.md | grep -E "curl|http"
```

---

## Workflow de Agentes

```
┌─────────────────────────────────────────────────────────────┐
│              AGENT WRITEUP CONSULTATION FLOW                │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. Detectar tecnologia/vulnerabilidad                      │
│                                                             │
│  2. Buscar writeups relevantes                              │
│     grep -r "[keyword]" .antigravity/writeups/                   │
│                                                             │
│  3. Leer writeups encontrados                               │
│     - Extraer tecnicas                                      │
│     - Extraer payloads                                      │
│     - Verificar que funciono                                │
│                                                             │
│  4. Adaptar tecnica al target actual                        │
│     - Cambiar URLs/endpoints                                │
│     - Ajustar payloads                                      │
│                                                             │
│  5. Ejecutar y documentar resultado                         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Tecnicas Documentadas en Writeups

### GraphQL (WRITEUP_graphql.md)
- Introspection query completa
- BOLA via user(id: X)
- IDOR via post(id: X)
- Batching attack con aliases
- Depth limiting bypass
- Error message extraction

### Kubernetes (CTF_Writeup_Kubernetes.md)
- Dynamic linker trick para binarios
- Lateral movement entre namespaces
- Token extraction desde pods
- kubectl exec pivoting
- API access via curl + token

### API Security (WRITEUP_apivault.md)
- JWT Algorithm Confusion (RS256 -> HS256)
- JWT alg:none bypass
- Race condition con threading
- SSRF a servicios internos
- Cache poisoning via X-Forwarded-Host
- Prototype pollution payloads
- Timing attack enumeration
- Mass assignment escalation
- OAuth redirect manipulation
- node-serialize RCE

---

## Reglas de Uso

### HACER
- Consultar writeups ANTES de probar tecnicas nuevas
- Adaptar payloads existentes al target actual
- Documentar que writeup se uso como referencia
- Agregar nuevos writeups al completar CTFs

### NO HACER
- Copiar payloads sin adaptar URLs
- Ignorar writeups existentes
- Reinventar tecnicas ya documentadas
- Olvidar actualizar el indice

---

## Actualizacion Automatica

> **Cuando se agregue un nuevo writeup:**
> 1. Colocarlo en `.antigravity/writeups/`
> 2. Actualizar este archivo con la categoria
> 3. Agregar a writeups-index.md (si existe)

---

## Integracion con Agentes

| Agente | Writeups Prioritarios |
|--------|----------------------|
| api-agent | WRITEUP_graphql.md, WRITEUP_apivault.md |
| auth-agent | WRITEUP_apivault.md (JWT, OAuth) |
| injection-agent | Todos los writeups web |
| cloud-agent | CTF_Writeup_Kubernetes.md, MediCloudX_* |
| race-condition-agent | WRITEUP_apivault.md (FLAG 3) |
| advanced-web-agent | WRITEUP_apivault.md (Cache, Prototype) |

---

**Version**: 2.0
**Actualizado**: 2026-01-30
**Writeups actuales**: 181
**CTFs organizados**: 23
