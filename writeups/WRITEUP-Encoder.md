# Encoder - CTF Writeup

## Información del Reto

- **Categoría**: Reversing
- **Nombre**: Encoder
- **Archivos**: `Encoder.exe` (PE32+ ejecutable para Windows x64)
- **Flag**: `FLAG{B33st_Enc0d33r}`

---

## Análisis Inicial

### Reconocimiento del Binario

Primero identifiqué el tipo de archivo:

```bash
file Encoder.exe
```

**Resultado**: `PE32+ executable for MS Windows 6.00 (console), x86-64, 7 sections`

Se trata de un ejecutable de Windows de 64 bits compilado en Rust (detectado por las referencias a rutas de Rust en el código descompilado).

### Extracción de Cadenas

Extraje las cadenas del binario para buscar pistas:

```bash
strings Encoder.exe | grep -E "flag|Flag|Great"
```

**Cadenas importantes encontradas**:
- `"Great job! Your flag is "`
- `"RKxBR6tcmzNzdF0FbMmWZDmzCn9="`
- Referencias a `crypto.rs`

Esto sugiere que:
1. El programa valida alguna entrada
2. Si es correcta, muestra un mensaje de éxito con la flag
3. La cadena `RKxBR6tcmzNzdF0FbMmWZDmzCn9=` parece ser Base64

---

## Análisis del Código Descompilado

### Función Principal

En el archivo `doc1.txt` (descompilado con Hex-Rays/IDA Pro), encontré la función `main` en la línea 6259:

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  return sub_140004DC0((__int64)sub_140006E00);
}
```

### Lógica de Validación

La función crítica `sub_140006E00` (líneas 6200-6250) implementa la lógica principal:

```c
// Línea 6228: Codifica la entrada del usuario
sub_140005E80(v16, v1, v2);

// Línea 6229: Compara con la cadena objetivo
if ( sub_140004B50(v16, (__int64 *)&off_140029BF8) )  // off_140029BF8 = "RKxBR6tcmzNzdF0FbMmWZDmzCn9="
{
  // Si coincide, muestra "Great job! Your flag is " + entrada original
  v19 = v13;
  v3 = sub_140004680((__int64)&v19);
  sub_140004770(v17, (__int64)&off_140029C20, 1, (__int64)v18, 1);  // "Great job! Your flag is "
  sub_1400106D0(v17);
}
```

**Flujo del programa**:
1. Lee la entrada del usuario
2. La codifica usando `sub_140005E80`
3. Compara el resultado con `"RKxBR6tcmzNzdF0FbMmWZDmzCn9="`
4. Si coincide, imprime "Great job! Your flag is " seguido de la entrada original

---

## Análisis de la Función de Codificación

### Función `sub_140005E80` (Línea 5924)

Esta función implementa una codificación tipo Base64 personalizada. Las operaciones de bits clave son:

```c
// Extrae bits de los bytes de entrada
v32 = sub_140006D80(*(_BYTE *)(a2 + i));      // Byte 0
v30 = sub_140006DA0(*(_BYTE *)(a2 + i), *(_BYTE *)(a2 + v31));  // Bytes 0-1
v27 = sub_140006DD0(*(_BYTE *)(a2 + v29), *(_BYTE *)(a2 + v28)); // Bytes 1-2
v25 = *(_BYTE *)(a2 + v26) & 0x3F;             // Byte 2

// Busca en tabla de lookup
v24 = v45[v32];  // Tabla copiada de unk_1400298E0
v23 = v46[v30];
v22 = v47[v27];
v4 = v48[v25];
```

### Funciones de Extracción de Bits

Encontré las funciones que extraen los índices para Base64:

```c
// sub_140006D80: Extrae bits 6-2 del byte (¡ignora el bit 7!)
char __fastcall sub_140006D80(char a1)
{
  return (unsigned __int8)(a1 & 0x7C) >> 2;
}

// sub_140006DA0: Combina bits 1-0 de a1 con bits 7-4 de a2
char __fastcall sub_140006DA0(char a1, char a2)
{
  return ((unsigned __int8)(a2 & 0xF0) >> 4) | (16 * (a1 & 3));
}

// sub_140006DD0: Combina bits 3-0 de a1 con bits 7-6 de a2
char __fastcall sub_140006DD0(char a1, char a2)
{
  return ((a2 & 0xC0) >> 6) | (4 * (a1 & 0xF));
}
```

Estas funciones implementan la extracción de bits característica de Base64, pero con una peculiaridad: **el bit 7 del primer byte se ignora**.

---

## Descubrimiento de la Tabla Base64 Personalizada

### Búsqueda de la Tabla

Todas las funciones de lookup usan una tabla copiada de `unk_1400298E0`. Extraje esta tabla del binario:

```bash
objdump -s -j .rdata Encoder.exe | grep -A 20 "298e0"
```

**Datos en 0x1400298E0** (en formato little-endian DWORD):
```
1400298e0: 61000000 42000000 63000000 44000000  a...B...c...D...
1400298f0: 65000000 46000000 67000000 48000000  e...F...g...H...
140029900: 69000000 4a000000 6b000000 4c000000  i...J...k...L...
...
1400299b0: 39000000 38000000 37000000 36000000  9...8...7...6...
1400299c0: 35000000 34000000 33000000 32000000  5...4...3...2...
1400299d0: 31000000 30000000 2b000000 2d000000  1...0...+...-...
```

### Extracción de la Tabla

Extrayendo el primer byte de cada DWORD, obtuve la **tabla Base64 personalizada**:

```
aBcDeFgHiJkLmNoPqRsTuVwXyZAbCdEfGhIjKlMnOpQrStUvWxYz9876543210+-
```

**Comparación con Base64 estándar**:

| Tipo | Tabla |
|------|-------|
| **Estándar** | `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/` |
| **Personalizada** | `aBcDeFgHiJkLmNoPqRsTuVwXyZAbCdEfGhIjKlMnOpQrStUvWxYz9876543210+-` |

**Diferencias**:
1. ✨ **Alterna mayúsculas y minúsculas**: a, B, c, D, e, F...
2. 🔢 **Números en orden inverso**: 9, 8, 7, 6, 5, 4, 3, 2, 1, 0
3. 🔄 **Caracteres especiales diferentes**: `+-` en vez de `+/`

---

## Decodificación de la Flag

### Script de Decodificación

Creé un script Python para traducir de la tabla personalizada a la estándar y decodificar:

```python
import base64

# Tabla base64 PERSONALIZADA del binario
custom_table = "aBcDeFgHiJkLmNoPqRsTuVwXyZAbCdEfGhIjKlMnOpQrStUvWxYz9876543210+-"
standard_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

# Cadena codificada encontrada en el binario
encoded_custom = "RKxBR6tcmzNzdF0FbMmWZDmzCn9="

# Crear tabla de traducción
translation = str.maketrans(custom_table, standard_table)

# Traducir de tabla personalizada a estándar
encoded_standard = encoded_custom.translate(translation)

print(f"Personalizada: {encoded_custom}")
print(f"Estándar:      {encoded_standard}")

# Decodificar con Base64 estándar
decoded = base64.b64decode(encoded_standard)

print(f"Decodificado:  {decoded.decode('utf-8')}")
```

### Resultado

```
Personalizada: RKxBR6tcmzNzdF0FbMmWZDmzCn9=
Estándar:      RkxBR3tCMzNzdF9FbmMwZDMzcn0=
Decodificado:  FLAG{B33st_Enc0d33r}
```

---

## Flag

```
FLAG{B33st_Enc0d33r}
```

---

## Resumen Técnico

1. **Tipo de codificación**: Base64 personalizada con tabla modificada
2. **Peculiaridades**:
   - Tabla con alternancia de mayúsculas/minúsculas
   - Dígitos en orden inverso
   - Caracteres especiales `+-` en lugar de `+/`
3. **Método de resolución**:
   - Análisis estático del binario
   - Extracción de la tabla de lookup de la sección `.rdata`
   - Traducción de tabla personalizada a estándar
   - Decodificación Base64

---

## Herramientas Utilizadas

- **IDA Pro / Hex-Rays Decompiler**: Análisis del código
- **objdump**: Extracción de datos del binario
- **Python**: Script de decodificación
- **strings**: Identificación de cadenas relevantes

---

## Autor

p0mb3r0

**Fecha**: 21 de Noviembre de 2025
