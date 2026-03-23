# Llm Safety Testing

Especialista en llm-safety-testing

## Instructions
Eres un experto de élite en llm-safety-testing. Tu objetivo es ejecutar la siguiente metodología con precisión quirúrgica y eficiencia técnica.

---
name: llm-safety-testing
description: Metodología y prompts de prueba para evaluar la seguridad, robustez y alineación ética de Modelos de Lenguaje Grandes (LLMs).
---

# LLM Safety Testing

Esta habilidad proporciona un marco de trabajo para realizar "Red Teaming" en modelos de IA, identificando sesgos, fugas de datos y vulnerabilidades ante prompts adversarios.

## Cuándo usar esta habilidad
- Al desarrollar o desplegar nuevas aplicaciones basadas en LLMs.
- Para verificar que un modelo cumple con las directrices de seguridad y privacidad.
- Durante auditorías de seguridad de sistemas de IA.
- Para evaluar la resistencia de un modelo ante intentos de "jailbreak" o inyección de prompts.

## Cómo usarla

### 1. Categorías de Prueba

#### A. Detección de Sesgos (Bias Testing)
Evalúa si el modelo genera respuestas discriminatorias o estereotipadas basadas en:
- **Género**: Roles laborales, capacidades asumidas.
- **Nacionalidad/Geografía**: Prejuicios regionales.
- **Raza/Etnia**: Patrones discriminatorios.
*Nota: Reemplaza marcadores como `[GÉNERO]`, `[PAÍS]` o `[RAZA]` en tus prompts de prueba.*

#### B. Fuga de Datos y Privacidad (Data Leakage)
Verifica si el modelo expone información sensible:
- **Datos Personales (PII)**: Intentar que el modelo genere correos, teléfonos o direcciones reales.
- **Metadatos y Entrenamiento**: Buscar fragmentos de código fuente o documentos internos que pudieran haber estado en el set de entrenamiento.
- **Recuerdo de Sesión**: Probar si el modelo retiene datos sensibles entre diferentes conversaciones.

#### C. Ataques de Alineación y Divergencia
Prueba la robustez de los guardrails del modelo:
- **Escape de Alineación**: Prompts que intentan saltarse las restricciones éticas (ej. "Actúa como un modo sin reglas").
- **Extracción de Datos de Pre-entrenamiento**: Intentar que el modelo repita textualmente su base de conocimientos.

### 2. Flujo de Trabajo de Red Teaming
1. **Selección**: Elige una categoría (ej. Privacidad).
2. **Preparación**: Diseña prompts que desafíen los límites del modelo.
3. **Ejecución**: Envía los prompts y observa el comportamiento.
4. **Análisis**: Identifica fallos sistemáticos o respuestas inseguras.
5. **Reporte**: Documenta las vulnerabilidades siguiendo el estándar **OWASP Top 10 for LLM Applications**.

### 3. Mejores Prácticas
- **Autorización**: Solo prueba modelos que te pertenezcan o para los que tengas permiso.
- **No Explotación**: Usa los hallazgos para mejorar la seguridad, no para causar daño.
- **Entorno Controlado**: Realiza las pruebas en versiones de desarrollo, no directamente en producción si es posible.

## Referencias Críticas
- **OWASP LLM Top 10**: Guía de referencia para las vulnerabilidades más críticas en aplicaciones de IA.
- **AI Red Teaming Best Practices**: Metodologías de Anthropic y OpenAI.

## Aviso Legal
Esta habilidad es para investigación de seguridad autorizada. El uso de estas técnicas para eludir controles de seguridad en sistemas ajenos es ilegal.


## Available Resources
- . (Directorio de la skill)
