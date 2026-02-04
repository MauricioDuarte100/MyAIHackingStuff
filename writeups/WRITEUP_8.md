# Writeup - CTF Mobile Challenge: Ultimactf

## Información del Reto

- **Nombre**: Ultimactf
- **Package**: com.lior.ultimactf
- **Tipo**: Android APK (desempaquetado con apktool)
- **Flag**: `ALP{L4_ult1m4_y_s3_d3c1d3_t0d0}`

---

## Análisis Inicial

### 1. Exploración del directorio

Al listar el contenido del directorio, encontramos una APK ya desempaquetada con apktool:

```bash
ls -la
```

Archivos relevantes:
- `AndroidManifest.xml` - Manifest de la aplicación
- `smali/`, `smali_classes2/`, `smali_classes3/` - Código descompilado en formato Smali
- `res/` - Recursos de la aplicación

### 2. Análisis del AndroidManifest.xml

El manifest revela:
- **Actividad principal**: `com.lior.ultimactf.MainActivity`
- **Package**: `com.lior.ultimactf`
- La aplicación está marcada como `debuggable="true"`

---

## Análisis del Código

### 3. Localización de archivos clave

Busqué los archivos Smali de la aplicación:

```bash
find . -path "*/com/lior/*" -name "*.smali"
```

Archivos encontrados en `smali_classes3/com/lior/ultimactf/`:
- **MainActivity.smali** - Actividad principal
- **Vault.smali** - Clase que contiene la flag encriptada

---

## MainActivity.smali - Análisis Detallado

### 4. Protecciones Anti-Análisis

La aplicación implementa dos métodos de detección:

#### a) Detección de Debugger (líneas 33-62)

```smali
.method private isDebugging()Z
    invoke-static {}, Landroid/os/Debug;->isDebuggerConnected()Z
    move-result v0
    if-nez v0, :cond_1

    invoke-static {}, Landroid/os/Debug;->waitingForDebugger()Z
    move-result v0
    if-eqz v0, :cond_0
```

Verifica si hay un debugger conectado usando `Debug.isDebuggerConnected()` y `Debug.waitingForDebugger()`.

#### b) Detección de Frida (líneas 64-125)

```smali
.method private looksLikeFrida()Z
    new-instance v2, Ljava/io/File;
    const-string v3, "/proc/self/maps"
    invoke-direct {v2, v3}, Ljava/io/File;-><init>(Ljava/lang/String;)V

    invoke-static {v2}, Ljava/nio/file/Files;->readAllBytes(Ljava/nio/file/Path;)[B

    const-string v2, "frida"
    invoke-virtual {v1, v2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    const-string v2, "gum-js-loop"
    invoke-virtual {v1, v2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z
```

Lee `/proc/self/maps` y busca las cadenas "frida" o "gum-js-loop".

**Resultado de las protecciones** (líneas 280-318):
- Si se detecta debugger o Frida, muestra "FLAG: nope 😉" y deshabilita el botón
- De lo contrario, continúa con la lógica normal

### 5. Lógica del Reto

#### a) Inicialización (líneas 273-277)

```smali
invoke-static {}, Lcom/lior/ultimactf/Vault;->decodeToBytes()[B
move-result-object v3
iput-object v3, p0, Lcom/lior/ultimactf/MainActivity;->flagInMemory:[B
```

La flag se decodifica y almacena en memoria usando `Vault.decodeToBytes()`.

#### b) Función buggySum (líneas 20-31)

```smali
.method private buggySum(II)I
    .param p1, "a"    # I
    .param p2, "b"    # I

    add-int v0, p1, p2      # v0 = a + b
    mul-int/lit8 v0, v0, 0x2  # v0 = v0 * 2
    return v0
.end method
```

**Problema**: En lugar de retornar `a + b`, retorna `(a + b) * 2`.
- Para `buggySum(5, 5)` retorna `20` en lugar de `10`

#### c) Función verify (líneas 127-148)

```smali
.method private verify(II)Z
    .param p1, "user"    # I
    .param p2, "expected"    # I

    xor-int/lit8 v0, p1, 0x55    # v0 = user XOR 0x55
    xor-int/lit8 v1, p2, 0x55    # v1 = expected XOR 0x55
    if-ne v0, v1, :cond_0         # if (v0 == v1)
```

Verifica si `user == expected` usando XOR con 0x55.

#### d) onClick Handler (líneas 152-223)

```smali
const/4 v0, 0x5              # a = 5
const/4 v1, 0x5              # b = 5
const/16 v2, 0xa             # userAnswer = 10 (0xa)

invoke-direct {p0, v0, v1}, buggySum  # expected = buggySum(5, 5) = 20
invoke-direct {p0, v2, v3}, verify    # verify(10, 20) = false
```

La verificación falla porque:
- `userAnswer = 10`
- `expected = buggySum(5, 5) = 20`
- `verify(10, 20)` retorna `false`

**Resultado**: Muestra "FLAG: C0rr1g3_l4_sum4 😈" (línea 216).

---

## Vault.smali - Extracción de la Flag

### 6. Array Encriptado (líneas 26-58)

```smali
.field private static final ENC:[I

.array-data 4
    0x79
    0x7e
    0x6a
    0x4f
    0x7e
    0x6
    0x6b
    0x45
    0x5e
    0x46
    0x9
    0x5d
    0x6
    0x6b
    0x51
    0x6b
    0x47
    0x7
    0x6b
    0x56
    0x7
    0x57
    0x9
    0x56
    0x7
    0x6b
    0x46
    0xa
    0x56
    0xa
    0x4d
.end array-data
```

### 7. Algoritmo de Decodificación (líneas 70-118)

```smali
.method public static decodeToBytes()[B
    sget-object v0, ENC:[I
    array-length v0, v0
    new-array v0, v0, [B

    :goto_0
    sget-object v2, ENC:[I
    aget v2, v2, v1

    add-int/lit8 v2, v2, -0x3    # x = ENC[i] - 3
    xor-int/lit8 v2, v2, 0x37     # x = x XOR 0x37

    int-to-byte v3, v2
    aput-byte v3, v0, v1

    add-int/lit8 v1, v1, 0x1
    goto :goto_0
```

**Algoritmo**:
1. Para cada valor en `ENC[i]`:
2. `x = ENC[i] - 3`
3. `x = x XOR 0x37`
4. Convertir a byte

---

## Solución

### 8. Script de Decodificación

Creé un script Python que implementa el algoritmo de decodificación:

```python
#!/usr/bin/env python3

# Array ENC from Vault.smali
ENC = [
    0x79, 0x7e, 0x6a, 0x4f, 0x7e, 0x6, 0x6b, 0x45, 0x5e, 0x46,
    0x9, 0x5d, 0x6, 0x6b, 0x51, 0x6b, 0x47, 0x7, 0x6b, 0x56,
    0x7, 0x57, 0x9, 0x56, 0x7, 0x6b, 0x46, 0xa, 0x56, 0xa, 0x4d
]

# Decoding algorithm from Vault.decodeToBytes()
def decode_flag():
    out = []
    for val in ENC:
        # Step 1: Subtract 3
        x = val - 3
        # Step 2: XOR with 0x37
        x = x ^ 0x37
        # Step 3: Convert to byte and append
        out.append(x & 0xFF)

    # Convert to string
    flag = bytes(out).decode('utf-8')
    return flag

if __name__ == "__main__":
    flag = decode_flag()
    print(f"FLAG: {flag}")
```

### 9. Ejecución

```bash
python3 decode_flag.py
```

**Resultado**:
```
FLAG: ALP{L4_ult1m4_y_s3_d3c1d3_t0d0}
```

---

## Resumen

### Vulnerabilidades Encontradas

1. **Flag hardcodeada**: La flag está almacenada en el código con un cifrado trivial
2. **Algoritmo débil**: XOR simple con una clave estática (0x37)
3. **Análisis estático suficiente**: No se requirió análisis dinámico ni bypass de protecciones

### Solución Alternativa

Aunque el reto sugiere usar **Frida** para parchear `buggySum()` en runtime, la solución más directa fue:
1. Extraer el array `ENC` del código Smali
2. Implementar el algoritmo de decodificación
3. Ejecutar el script para obtener la flag

### Lecciones Aprendidas

- Las protecciones anti-debug/anti-Frida pueden bypassearse con análisis estático
- Los algoritmos de cifrado deben ser robustos y no depender de "security by obscurity"
- Almacenar flags encriptadas en el código fuente es una mala práctica

---

## Flag Final

```
ALP{L4_ult1m4_y_s3_d3c1d3_t0d0}
```

**Traducción**: "ALP{La última y se decide todo}" 🎯
