# Solución del Reto "CÓDIGO ROBADO" - Estado Actual

## 🎯 Objetivo del Reto
- **Nombre**: CÓDIGO ROBADO (Stolen Code)
- **Plataforma**: ThePwnLab
- **Categoría**: Forense / Side-Channel Analysis
- **Creadora**: Ilana Aminoff
- **Fecha**: 09/05/2025
- **Hash objetivo**: `SECRET_REDACTED_BY_ANTIGRAVITY56989d7d5b5e3e2470d2f704`

---

## ✅ LO QUE YA RESOLVIMOS

### Clave AES Recuperada (CPA exitoso)

**Modelo usado**: Direct S-box value (sin Hamming Weight)

```
Byte 0: 0xAB  (correlación: 0.9794, sample: 1376)
Byte 1: 0xB2  (correlación: 0.9781, sample: 1867)
Byte 2: 0xFF  (correlación: 0.9782, sample: 1709)
Byte 3: 0xE7  (correlación: 0.9763, sample: 1614)
```

**Clave parcial confiable**: `abb2ffe7`

**Clave completa candidata** (bytes 4-15 con correlación ~0.15, NO confiables):
```
abb2ffe716b623b4d6ceab94a9b82e98
```

### Scripts Funcionales Creados

1. **`solve_direct_model.py`** - Ataque CPA con modelo directo (el mejor)
2. **`test_flag.py`** - Prueba rápida de candidatos
3. **`advanced_analysis.py`** - Análisis exhaustivo de todas las ideas
4. **`test_challenge_name.py`** - Formatos relacionados con el nombre del reto

---

## ❌ LO QUE NO PUDIMOS RESOLVER

A pesar de probar **más de 400 combinaciones diferentes**, ninguna genera el hash objetivo.

### Formatos Probados Sin Éxito:

#### Formatos Básicos
- ❌ `abb2ffe7` (hex lowercase)
- ❌ `ABB2FFE7` (hex uppercase)
- ❌ `abb2ffe716b623b4d6ceab94a9b82e98` (clave completa)
- ❌ Base64 de la clave
- ❌ Decimal (little/big endian)

#### Formatos CTF
- ❌ `TPL{abb2ffe7}`
- ❌ `TPL{abb2ffe716b623b4d6ceab94a9b82e98}`
- ❌ `flag{...}`, `FLAG{...}`, `ThePwnLab{...}`, etc.
- ❌ Todas las variaciones mayúsculas/minúsculas

#### Formatos Relacionados con el Reto
- ❌ `TPL{CODIGO_ROBADO}`
- ❌ `TPL{CODIGO_ROBADO_abb2ffe7}`
- ❌ `TPL{SILICIO_...}`
- ❌ `TPL{CPA_...}`
- ❌ `TPL{FORENSE_...}`
- ❌ Con y sin acentos (CÓDIGO)

#### Técnicas Avanzadas
- ❌ Cifrado AES de plaintexts con la clave
- ❌ XOR de plaintexts
- ❌ Derivación con PBKDF2/KDF
- ❌ Interpretación como índices/punteros
- ❌ Steganografía en trazas
- ❌ Búsqueda de ASCII en datos
- ❌ Hashes (MD5, SHA1, SHA256, SHA512) de la clave

---

## 🔍 POSIBLES EXPLICACIONES

1. **Falta información del enunciado completo**
   - El archivo `datos-siliciio.txt` solo tiene el anuncio general
   - No tenemos la descripción específica del reto en ThePwnLab
   - Puede haber hints, pistas o formato específico de flag

2. **Reto con múltiples flags**
   - El archivo menciona "múltiples flags"
   - Quizás hay que resolver otra parte primero
   - Pueden ser varias preguntas/pasos

3. **Archivos adicionales faltantes**
   - Solo tenemos: `plaintext.npy`, `traces.npy`, `flag.txt`
   - Puede haber otros archivos en el reto original

4. **El hash no es de la flag final**
   - Podría ser un hash de verificación de datos
   - La flag real podría submitearse directamente sin hash

5. **Necesitamos recuperar los 16 bytes completos**
   - Técnicas avanzadas: Template Attack, Deep Learning, ASCA
   - Ataque a la segunda ronda de AES
   - Análisis de masking schemes

---

## 📋 PRÓXIMOS PASOS RECOMENDADOS

### 1. Acceder a ThePwnLab (CRÍTICO)

**URL**: https://thepwnlab.com

**Qué buscar**:
- [ ] Descripción completa del reto "CÓDIGO ROBADO"
- [ ] Hints o pistas disponibles
- [ ] Formato específico de la flag
- [ ] Preguntas múltiples (si las hay)
- [ ] Otros archivos descargables
- [ ] Campo de submit (¿pide hash o flag directa?)
- [ ] Writeups o soluciones parciales de otros usuarios
- [ ] Foro de discusión del reto

### 2. Verificar Archivos Descargados

Asegurarse de tener TODOS los archivos del reto:
- [ ] ¿Hay más archivos .npy?
- [ ] ¿Hay archivos .txt con instrucciones?
- [ ] ¿Hay imágenes, PDFs, o documentos adicionales?
- [ ] ¿El archivo flag.txt es el correcto?

### 3. Usar el Script de Prueba Rápida

Cuando tengas el formato de la flag:

```bash
python3 test_flag.py "TPL{tu_candidato_aqui}"
```

### 4. Si Necesitás Recuperar Todos los Bytes

Técnicas avanzadas (requieren más tiempo/recursos):
- Template Attack
- Deep Learning (CNN sobre trazas)
- Algebraic Side-Channel Analysis (ASCA)
- Ataque a segunda ronda de AES
- Análisis de masking schemes

---

## 📊 RESUMEN TÉCNICO

### Datos del Análisis

| Aspecto | Valor |
|---------|-------|
| Plaintexts | 1000 bloques de 16 bytes |
| Traces | 1000 trazas de 4000 samples |
| Modelo CPA | Direct S-box value |
| Correlación máxima | 0.9794 |
| Bytes confiables | 4 de 16 (25%) |
| Bytes no confiables | 12 de 16 (75%) |
| Formatos probados | >400 |
| Coincidencias | 0 |

### Conclusión

**Hemos alcanzado el límite de lo que se puede resolver con los datos disponibles.**

La solución técnica (recuperación de clave AES mediante CPA) está **completa y correcta** para los 4 bytes que filtran información.

El problema es que **no sabemos el formato exacto de la flag** que espera la plataforma.

---

## 🆘 CONTACTO Y RECURSOS

### Si Necesitás Más Ayuda

Cuando obtengas más información del reto:
1. Compartir la descripción completa del enunciado
2. Compartir hints o pistas disponibles
3. Confirmar si hay archivos adicionales
4. Indicar el formato de submit (hash vs flag directa)

### Scripts Listos para Usar

- `test_flag.py` - Prueba rápida de cualquier candidato
- `solve_direct_model.py` - Vuelve a ejecutar el CPA
- `advanced_analysis.py` - Análisis exhaustivo

### Datos Clave para Copiar/Pegar

```
Clave parcial (4 bytes): abb2ffe7
Clave completa candidata: abb2ffe716b623b4d6ceab94a9b82e98
Hash objetivo: SECRET_REDACTED_BY_ANTIGRAVITY56989d7d5b5e3e2470d2f704
```

---

**Última actualización**: Noviembre 2025
**Estado**: ✅ Clave recuperada | ❌ Flag no encontrada (falta información del enunciado)
