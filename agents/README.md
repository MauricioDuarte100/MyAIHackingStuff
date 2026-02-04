# 🤖 Agentes Integrados

Este directorio contiene agentes especializados que complementan los skills internos del framework.

## Arquitectura de Agentes

```
┌─────────────────────────────────────────────────────────────────┐
│                    UNIFIED-ORCHESTRATOR                         │
│              (Coordinador Principal Unificado)                  │
└─────────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌───────────────┐     ┌───────────────┐     ┌───────────────┐
│   DISCOVERY   │     │   ANALYSIS    │     │   EXPLOIT     │
│    LAYER      │     │    LAYER      │     │    LAYER      │
└───────────────┘     └───────────────┘     └───────────────┘
        │                     │                     │
        ▼                     ▼                     ▼
┌───────────────┐     ┌───────────────┐     ┌───────────────┐
│ • recon-agent │     │ • code-review │     │ • injection   │
│ • backend-    │     │ • security-   │     │ • penetration │
│   architect   │     │   auditor     │     │   tester      │
│               │     │ • api-security│     │ • cloud-agent │
└───────────────┘     └───────────────┘     └───────────────┘
        │                     │                     │
        └─────────────────────┼─────────────────────┘
                              ▼
                    ┌───────────────┐
                    │   REPORTING   │
                    │    LAYER      │
                    │ • python-pro  │
                    │ • doc-agent   │
                    └───────────────┘
```

## Mapeo de Agentes

| Agente Externo | Complementa Skill | Función Principal |
|----------------|-------------------|-------------------|
| penetration-tester | injection-agent, cloud-agent | Explotación y post-explotación |
| security-auditor | auth-agent | Auditoría OWASP, JWT, OAuth |
| api-security-audit | api-agent | Auditoría específica de APIs |
| backend-architect | recon-agent | Entender arquitectura del target |
| code-reviewer | documentation-agent | Revisar exploits y PoCs |
| python-pro | Todos | Escribir herramientas de calidad |

## Cuándo Usar Cada Agente

### Fase 1: Reconocimiento
- `recon-agent` → Enumeración inicial
- `backend-architect` → Inferir arquitectura del sistema

### Fase 2: Análisis
- `security-auditor` → Auditoría OWASP sistemática
- `api-security-audit` → Análisis profundo de APIs
- `code-reviewer` → Revisar código JS/responses

### Fase 3: Explotación
- `penetration-tester` → Explotar vulnerabilidades
- `injection-agent` → SQLi, NoSQLi, SSTI
- `cloud-agent` → Cloud misconfigs, SSRF

### Fase 4: Reporting
- `python-pro` → Scripts de PoC profesionales
- `documentation-agent` → Generar reportes

## Invocación de Agentes

Los agentes usan el formato de Antigravity Code:

```bash
# Invocar agente específico
antigravity --agent penetration-tester "Explotar IDOR en /api/users/{id}"

# Invocar con contexto
antigravity --agent security-auditor "Auditar JWT implementation en responses capturados"

# Combinar agentes
antigravity --agent api-security-audit "Analizar GraphQL schema" | antigravity --agent penetration-tester "Explotar"
```
