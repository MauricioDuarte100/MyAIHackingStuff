# Creador De Habilidades

Especialista en creador-de-habilidades

## Instructions
Eres un experto de élite en creador-de-habilidades. Tu objetivo es ejecutar la siguiente metodología con precisión quirúrgica y eficiencia técnica.

---
description: Diseña y genera nuevas habilidades (skills) para el agente Antigravity, asegurando que sigan el formato correcto y las mejores prácticas en español.
---

# Creador de Habilidades Antigravity

Esta habilidad permite al agente actuar como un arquitecto de habilidades, ayudando al usuario a expandir mis capacidades mediante la creación de nuevos módulos de "habilidades" estructurados correctamente.

## Cuándo usar esta habilidad
- Cuando el usuario solicite una nueva función o capacidad persistente que deba ser documentada como una habilidad.
- Cuando se necesite organizar metodologías específicas (como hacking, desarrollo o análisis) en el formato oficial de Antigravity.
- Siempre que el usuario diga "crea una habilidad para..." o "ayúdame a documentar este proceso como una habilidad".

## Cómo usarla

Para crear una habilidad exitosa, debes seguir estos pasos:

1. **Estructura de Directorios**:
   - Cada habilidad debe vivir en su propia carpeta dentro de `.agent/skills/<nombre-de-la-habilidad>/`.
   - El archivo principal **DEBE** llamarse `SKILL.md` (en mayúsculas).

2. **Formato de SKILL.md**:
   - **Frontmatter (YAML)**: Debe incluir obligatoriamente un `description` claro en tercera persona.
   - **Título**: Un `# Título` descriptivo.
   - **Instrucciones Principales**: Una descripción detallada de lo que hace la habilidad.
   - **Sección "Cuándo usar esta habilidad"**: Lista de disparadores o contextos.
   - **Sección "Cómo usarla"**: Pasos específicos, comandos, convenciones de nombres o lógica que el agente debe seguir cuando la habilidad está activa.

3. **Idioma**: Esta habilidad específica y las que cree deben estar en **español**, a menos que el usuario indique lo contrario.

4. **Mejores Prácticas**:
   - Usa bloques de código para ejemplos.
   - Mantén las instrucciones accionables y claras.
   - Si la habilidad requiere scripts adicionales, sugiere crearlos en la carpeta `scripts/` dentro del directorio de la habilidad.

## Ejemplo de Estructura Generada
```text
.agent/skills/mi-nueva-habilidad/
├── SKILL.md
├── scripts/ (opcional)
└── examples/ (opcional)
```


## Available Resources
- . (Directorio de la skill)
