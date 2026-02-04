# Auto-Learning Rules

Este archivo define el comportamiento automático de actualización de lecciones aprendidas.

---

## REGLA: Actualización Automática de Lecciones

> **Antigravity DEBE actualizar automáticamente `.antigravity/knowledge/lessons-learned.md` cuando:**
> 1. Un reporte es rechazado o marcado N/A
> 2. Se descubre un false positive
> 3. Se corrige la severidad de un hallazgo
> 4. Se identifica un patrón que evitaría errores futuros

---

## Triggers de Auto-Aprendizaje

### 1. Rechazo de Bugcrowd
```yaml
trigger: "Reporte rechazado o N/A"
action: |
  1. Documentar el error en lessons-learned.md
  2. Agregar checklist de prevención
  3. Actualizar validador correspondiente si aplica
```

### 2. False Positive Identificado
```yaml
trigger: "Hallazgo resulta ser false positive"
action: |
  1. Documentar en lessons-learned.md bajo "LECCION N"
  2. Incluir: qué reportamos, por qué era inválido, cómo evitarlo
  3. Agregar comandos de validación si aplica
```

### 3. Corrección de Severidad
```yaml
trigger: "Severidad original era incorrecta"
action: |
  1. Documentar la corrección
  2. Explicar por qué el CVSS original era incorrecto
  3. Agregar regla para futuros casos similares
```

### 4. Nuevo Patrón Descubierto
```yaml
trigger: "Se identifica técnica que funciona/no funciona"
action: |
  1. Documentar resultado en lessons-learned.md
  2. Si funciona: agregar a prioridades
  3. Si no funciona: agregar a deprioritizar
```

---

## Formato de Nueva Lección

```markdown
## LECCION N: [Título descriptivo]

**Caso**: [ID del caso, ej: UA-2026-XXX]
**Fecha**: [YYYY-MM-DD]

### El Error
- Qué reportamos/asumimos incorrectamente

### La Realidad
- Por qué era incorrecto

### Validación
- Comandos o checks para evitar este error

### Regla
> Resumen en una línea de la lección
```

---

## Archivos a Actualizar Automáticamente

| Situación | Archivo a Actualizar |
|-----------|---------------------|
| Nueva lección general | `.antigravity/knowledge/lessons-learned.md` |
| Nueva regla de validación | `.antigravity/rules/validation-rules.md` |
| Cambio en metodología OWASP | `.antigravity/rules/owasp-2025.md` |
| Nuevo skill/validador | `.antigravity/skills/[nombre]/SKILL.md` |

---

## Ejemplo de Auto-Actualización

### Cuando ocurra esto:
```
User: "Este reporte fue rechazado porque CORS wildcard no es explotable"
```

### Antigravity DEBE hacer automáticamente:
1. Leer `.antigravity/knowledge/lessons-learned.md`
2. Agregar nueva lección con formato estándar
3. Actualizar `validation-rules.md` si aplica
4. Confirmar al usuario que se actualizó

### NO esperar a que el usuario diga:
- "Actualiza las lecciones"
- "Documenta esto"
- "Agrega esta regla"

---

## Comportamiento Esperado

```
┌─────────────────────────────────────────────────────────────┐
│                    AUTO-LEARNING FLOW                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. Detectar evento de aprendizaje                          │
│     ├── Rechazo                                             │
│     ├── False positive                                      │
│     ├── Corrección                                          │
│     └── Nuevo patrón                                        │
│                                                             │
│  2. Actualizar knowledge/lessons-learned.md                 │
│     └── Sin esperar instrucción del usuario                 │
│                                                             │
│  3. Actualizar rules/ si corresponde                        │
│                                                             │
│  4. Informar al usuario                                     │
│     └── "Lección documentada en lessons-learned.md"         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Palabras Clave que Activan Auto-Learning

- "rechazado"
- "N/A"
- "false positive"
- "no explotable"
- "corregir severidad"
- "bajar a P3/P4"
- "error cometido"
- "no funciona"
- "bloqueado"
- "withdrawn"

---

**Versión**: 1.0
**Creado**: 2026-01-30
