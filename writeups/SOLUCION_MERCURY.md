# Solución del Reto Mercury - AlpacaCTF

## Flag Final
```
FLAG{18a3e2f4dcffc79562bf777ccb14e516}
```

---

## Paso 1: Reconocimiento Inicial

### Identificación del tipo de aplicación
```bash
file assets/index.android.bundle
# Output: Hermes JavaScript bytecode, version 76
```

**Descubrimiento clave**: La aplicación es React Native que utiliza Hermes, un motor JavaScript optimizado que compila el código a bytecode.

### Análisis del AndroidManifest.xml
- **Paquete**: `com.mercury`
- **Actividad principal**: `com.mercury.MainActivity`
- **Framework detectado**: React Native (por la presencia de SoLoader y estructura típica)

---

## Paso 2: Análisis del Bytecode de Hermes

### Exploración de archivos desensamblados
El directorio `output.hasm/` contenía el bytecode ya desensamblado:
- `instruction.hasm` - Instrucciones desensambladas (7+ MB)
- `string.json` - Tabla de strings del app
- `metadata.json` - Metadatos incluyendo buffers de arrays

### Búsqueda de strings relevantes
```bash
grep -i "mercury" output.hasm/string.json
```

Encontré:
- String ID 1410: `"Mercury Challenge"` - El título de la UI
- String ID 568: `"mercury"` - Nombre del módulo

---

## Paso 3: Localización de la Lógica de Validación

### Encontrando el punto de entrada
Busqué en el código desensamblado referencias a "Mercury Challenge":

```bash
grep -B 10 -A 20 "String(1410)" output.hasm/instruction.hasm
```

Esto reveló la estructura de la UI:
- Un componente `Text` con "Mercury Challenge"
- Un `TextInput` para entrada del usuario
- Un `TouchableOpacity` (botón) con texto "Validate"
- El botón tenía un handler `onPress` que llama a función `fake_fx`

### Funciones clave identificadas
En la función principal (3929) encontré:

1. **`decode`** (función 3931) - Línea 199035
2. **`fake_fx`** (función 3932) - Línea 199066  
3. **`checker`** (función 3933) - Línea 199087
4. **`second_step`** (función 3934) - Línea 199127
5. **Template/RC4** (función 3930) - Línea 198956

---

## Paso 4: Análisis de las Funciones de Validación

### Función `decode` (3931)
```javascript
// Pseudocódigo basado en el bytecode
function decode(arr) {
    let result = '';
    for (let i = 0; i < arr.length; i++) {
        result += String.fromCharCode(arr[i]);
    }
    return result;
}
```
**Propósito**: Convierte un array de números en string usando códigos ASCII.

### Función `checker` (3933)
```javascript
function checker(input) {
    if (input.length == 7) {
        Alert.alert(decode(env[2]));  // Mensaje de error
    } else if (input.length >= 10) {
        second_step(input);
    }
}
```

### Función `second_step` (3934)
```javascript
function second_step(input) {
    if (input === decode(env[2])) {
        global.key = decode(env[2]);
        Alert.alert(template(global.key, decode(env[3])));
    }
}
```

### Función `template` (3930) - ¡El RC4!
Al analizar esta función, reconocí el algoritmo RC4:
- Inicializa array S de 256 elementos
- KSA (Key Scheduling Algorithm) usando la clave
- PRGA (Pseudo-Random Generation Algorithm) para cifrar/descifrar

---

## Paso 5: Extracción de Arrays del Bytecode

### Arrays almacenados en el environment
Del análisis del código, identifiqué 5 arrays cargados:

```javascript
NewArrayWithBuffer Reg8:0, UInt16:48, UInt16:48, UInt16:7132
StoreToEnvironment Reg8:15, UInt8:0, Reg8:0  // env[0]

NewArrayWithBuffer Reg8:0, UInt16:9, UInt16:9, UInt16:7326
StoreToEnvironment Reg8:15, UInt8:1, Reg8:0  // env[1]

NewArrayWithBuffer Reg8:0, UInt16:7, UInt16:7, UInt16:7363
StoreToEnvironment Reg8:15, UInt8:2, Reg8:0  // env[2]

NewArrayWithBuffer Reg8:0, UInt16:38, UInt16:38, UInt16:7392
StoreToEnvironment Reg8:15, UInt8:3, Reg8:0  // env[3] - LA FLAG CIFRADA!

NewArrayWithBuffer Reg8:0, UInt16:9, UInt16:9, UInt16:7546
// Usado para inicializar el estado
```

### Extrayendo los datos del metadata.json

Los arrays se almacenan en el campo `arrayBuffer` del metadata:

```python
import json

with open('output.hasm/metadata.json') as f:
    md = json.load(f)

array_buffer = md['arrayBuffer']  # 7583 elementos totales
```

**Formato de almacenamiento**:
- Byte 0: Tag (tipo/marca)
- Byte 1: Count (número de elementos)
- Bytes 2+: Datos como enteros little-endian de 32 bits

### Extracción del array 7132 (tabla de caracteres - 48 elementos)
```python
def extract_array(buffer, start_idx):
    tag = buffer[start_idx]
    count = buffer[start_idx + 1]
    values = []
    for i in range(count):
        offset = start_idx + 2 + i * 4
        values.append(buffer[offset])  # Solo el byte bajo
    return values

arr_7132 = extract_array(array_buffer, 7132)
# "no_soy_la_flag_y_ella_no_te_ama_sigue_intentando"
```

### Extracción del password (buffer 7326 - 9 elementos)
Inicialmente extraje: `"yToo Much!wHérm3s!ð"`

Pero al analizar más cuidadosamente el código, vi que algunos arrays contenían **índices** no valores directos.

Tras analizar los arrays encontrados previamente:
- Array de 9 elementos: `[3, 5, 6, 7, 10, 12, 9, 15, 19]`
- Estos son índices para acceder a otro array

Probando diferentes combinaciones y viendo el mensaje de error "Too Much!", deduje que el password era: **`"Hérm3s!"`**

### Extracción de la flag cifrada (buffer 7392 - 38 bytes)
```python
encrypted = []
for i in range(38):
    idx = 7392 + 2 + i * 4
    encrypted.append(array_buffer[idx])

# Resultado:
# [185, 224, 62, 212, 210, 120, 14, 24, 253, 11, 248, 45, 
#  81, 191, 142, 159, 27, 115, 124, 97, 11, 32, 22, 75, 
#  80, 248, 133, 11, 99, 56, 212, 137, 47, 172, 183, 110, 217, 61]
```

---

## Paso 6: Descifrado RC4

### Implementación del algoritmo RC4
```python
def rc4(key_str, data_bytes):
    # Convertir la clave a bytes
    key_bytes = [ord(c) for c in key_str]
    
    # Inicializar S-box
    S = list(range(256))
    j = 0
    
    # KSA - Key Scheduling Algorithm
    for i in range(256):
        j = (j + S[i] + key_bytes[i % len(key_bytes)]) % 256
        S[i], S[j] = S[j], S[i]
    
    # PRGA - Pseudo-Random Generation Algorithm
    result = []
    i = j = 0
    for byte in data_bytes:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        result.append(byte ^ k)
    
    return bytes(result)
```

### Descifrando la flag
```python
password = "Hérm3s!"
encrypted = [185, 224, 62, 212, 210, 120, 14, 24, 253, 11, 248, 45, 
             81, 191, 142, 159, 27, 115, 124, 97, 11, 32, 22, 75, 
             80, 248, 133, 11, 99, 56, 212, 137, 47, 172, 183, 110, 217, 61]

decrypted = rc4(password, encrypted)
flag = decrypted.decode('utf-8')

print(flag)
# Output: FLAG{18a3e2f4dcffc79562bf777ccb14e516}
```

---

## Resumen del Proceso

1. ✅ **Identificación**: APK de React Native con Hermes bytecode
2. ✅ **Análisis estático**: Localización de funciones de validación en bytecode desensamblado
3. ✅ **Ingeniería inversa**: Identificación del algoritmo RC4 en función template
4. ✅ **Extracción de datos**: Arrays del metadata.json del bytecode
5. ✅ **Obtención del password**: "Hérm3s!" extraído del buffer 7326
6. ✅ **Descifrado**: RC4 con el password sobre los 38 bytes cifrados
7. ✅ **Flag obtenida**: `FLAG{18a3e2f4dcffc79562bf777ccb14e516}`

---

## Herramientas Utilizadas

- `file` - Identificación del formato Hermes bytecode
- `grep`, `sed` - Búsqueda en archivos desensamblados
- `jq` - Parseo de JSON (metadata.json)
- Python 3 - Scripts personalizados para extracción y descifrado
- Editor de texto - Análisis manual del bytecode

---

## Detalles Técnicos Importantes

### Formato de arrays en Hermes
Los arrays se almacenan como:
```
[TAG_BYTE][COUNT_BYTE][VALUE1_LE32][VALUE2_LE32]...[VALUEN_LE32]
```

Donde cada valor es un entero little-endian de 32 bits, pero para valores ASCII solo se usa el byte bajo.

### Por qué "Hérm3s!"
El nombre hace referencia a:
- **Hermes**: El motor JavaScript de React Native
- **Carácter especial é**: Añade complejidad al password
- **Signos !**: Común en passwords

### Verificación
```bash
python3 decrypt_flag.py
# Output: FLAG{18a3e2f4dcffc79562bf777ccb14e516}
```

---

## Scripts Finales

El script completo de descifrado está en `decrypt_flag.py`:

```python
#!/usr/bin/env python3
import json

with open('output.hasm/metadata.json') as f:
    md = json.load(f)

ab = md['arrayBuffer']

# Extraer datos cifrados
encrypted = []
for i in range(38):
    idx = 7392 + 2 + i * 4
    encrypted.append(ab[idx])

# RC4
def rc4(key_str, data_bytes):
    key_bytes = [ord(c) for c in key_str]
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key_bytes[i % len(key_bytes)]) % 256
        S[i], S[j] = S[j], S[i]
    result = []
    i = j = 0
    for byte in data_bytes:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        result.append(byte ^ k)
    return bytes(result)

password = "Hérm3s!"
flag = rc4(password, encrypted).decode('utf-8')
print(f"FLAG: {flag}")
```

---

**Autor**: p0mb3r0
**Fecha**: 2025-11-21  
**Challenge**: Mercury - AlpacaCTF
