# Writeup: Viejo Pascuero - Malwarespace CTF 2025

**Categoría:** Reversing / Crypto
**Dificultad:** Media-Alta
**Flag:** `3l_vi3j1t0_p4scu3ro!@malwarespace.com`

---

## Descripción del Reto

Se nos proporciona un ejecutable de Windows `main.exe` que solicita una contraseña. El objetivo es encontrar la contraseña correcta y obtener la flag oculta.

---

## Análisis Inicial

### Reconocimiento del archivo

```bash
$ file main.exe
main.exe: PE32+ executable (console) x86-64, for MS Windows
```

### Extracción de strings relevantes

```bash
$ strings main.exe | grep -i password
password:
[!] Invalid password length
[+] invalid password!
AUC.hmO78Tw+4TJECG8VlIbEjQa_Rf0QnZZ0
```

Encontramos una string interesante: `AUC.hmO78Tw+4TJECG8VlIbEjQa_Rf0QnZZ0` (36 caracteres) que parece ser una clave o pista.

### Análisis de recursos embebidos

Usando 7-Zip para extraer los recursos del PE:

```bash
$ 7z l main.exe
   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2025-12-10 20:20:39 .....       275968       275968  .text
2025-12-10 20:20:39 .....        44032        44032  .rdata
2025-12-10 20:20:39 .....         3072         3072  .data
2025-12-10 20:20:39 .....         5632         5632  .pdata
                    .....      2167459      2167459  .rsrc/RCDATA/101
                    .....          381          381  .rsrc/MANIFEST/1
```

Hay un recurso RCDATA/101 de **2.1 MB** embebido en el ejecutable.

```bash
$ 7z e main.exe -oresources -y
```

---

## Paso 1: Análisis del Recurso Cifrado

Examinamos los primeros bytes del recurso extraído:

```bash
$ xxd resources/101 | head -5
00000000: fd38 7f34 523b 6955 7468 3352 3929 3721  .8.4R;iUth3R9)7!
00000010: 7730 7664 5f75 5b72 576a 3030 6b4e 734c  w0vd_u[rWj00kNsL
00000020: dc66 3072 751b 6334 1d31 dd91 6881 335f  .f0ru.c4.1..h.3_
00000030: 7065 1432 3a71 7264 eefa 548e 3e69 3030  pe.2:qrd..T.>i00
00000040: 6b38 1e2f 0615 3072 7aab 3173 51f2 7298  k8./..0rz.1sQ.r.
```

Los datos parecen estar cifrados con XOR. Notamos algunos caracteres ASCII mezclados con bytes de alto valor.

---

## Paso 2: Derivación de la Clave XOR usando Estructura PNG

### Hipótesis: El recurso es un PNG cifrado con XOR

El header de un archivo PNG es: `89 50 4E 47 0D 0A 1A 0A` (`\x89PNG\r\n\x1a\n`)

Si XOR-eamos los primeros 8 bytes del recurso con el header PNG esperado:

```python
data = open('resources/101', 'rb').read()
png_header = b'\x89PNG\r\n\x1a\n'

key_part1 = bytes([a ^ b for a, b in zip(data[:8], png_header)])
print(f'Key part 1: {key_part1}')
# Output: b'th1s_1s_'
```

**Resultado:** Los primeros 8 bytes de la clave son `th1s_1s_`

### Extendiendo la clave usando la estructura PNG

Un archivo PNG tiene una estructura bien definida:

| Offset | Contenido | Bytes Esperados |
|--------|-----------|-----------------|
| 0-7 | PNG Signature | `89 50 4E 47 0D 0A 1A 0A` |
| 8-11 | IHDR Length | `00 00 00 0D` (13 bytes) |
| 12-15 | Chunk Type | `IHDR` |
| 16-19 | Width | Variable |
| 20-23 | Height | Variable |
| 24 | Bit Depth | 1,2,4,8,16 |
| 25 | Color Type | 0,2,3,4,6 |
| 26-28 | Compression, Filter, Interlace | Típicamente `00 00 00` |

Usando estos puntos de anclaje, derivamos más bytes de la clave:

```python
# IHDR length (offset 8-11)
ihdr_len = b'\x00\x00\x00\x0d'
key_8_11 = bytes([data[8+i] ^ ihdr_len[i] for i in range(4)])
# Result: b'th3_'

# IHDR name (offset 12-15)
ihdr_name = b'IHDR'
key_12_15 = bytes([data[12+i] ^ ord(ihdr_name[i]) for i in range(4)])
# Result: b'pass'
```

**Clave parcial:** `th1s_1s_th3_pass`

### Usando chunks adicionales para completar la clave

Después del chunk IHDR, los PNG típicamente tienen chunks como `sRGB` y `gAMA`:

```python
# Verificando chunk sRGB en offset 37-40
# key[37%36]=key[1], key[38%36]=key[2]...
chunks = [b'sRGB', b'gAMA', b'pHYs', b'IDAT']

for chunk in chunks:
    derived = bytes([data[37+i] ^ chunk[i] for i in range(4)])
    print(f'{chunk}: key[1:5] = {derived}')

# sRGB: key[1:5] = b'h1s_'  <-- ¡Coincide con 'th1s_'!
```

Continuando con el chunk `gAMA` en offset 50:
```python
# gAMA confirma key[14:18] = 'ssw0'
# Extendiendo: th1s_1s_th3_passw0
```

### Clave completa de 36 caracteres

Usando múltiples puntos de referencia del PNG (chunks sRGB, gAMA, pHYs), derivamos la clave completa:

```python
# Fragmentos derivados:
# key[0:18]  = 'th1s_1s_th3_passw0'
# key[18:22] = 'rd_u'     (de gAMA data)
# key[26:30] = '00k1'     (de pHYs length)
# key[30:34] = 'ng_f'     (de pHYs chunk name)

# Probando combinaciones que formen palabras con sentido:
test_key = b'th1s_1s_th3_passw0rd_u_r_l00k1ng_f0r'  # 36 chars
```

### Validación de la clave

```python
data = open('resources/101', 'rb').read()
key = b'th1s_1s_th3_passw0rd_u_r_l00k1ng_f0r'

dec = bytes([data[i] ^ key[i % 36] for i in range(100)])

# Verificar IHDR
width = int.from_bytes(dec[16:20], 'big')   # 1024
height = int.from_bytes(dec[20:24], 'big')  # 1024
bit_depth = dec[24]                          # 8
color_type = dec[25]                         # 6 (RGBA)
compression = dec[26]                        # 0
filter_method = dec[27]                      # 0

print(f'Dimensions: {width}x{height}')
print(f'Valid PNG: True')
```

**Clave encontrada:** `th1s_1s_th3_passw0rd_u_r_l00k1ng_f0r`

---

## Paso 3: Extracción del PNG

```python
data = open('resources/101', 'rb').read()
key = b'th1s_1s_th3_passw0rd_u_r_l00k1ng_f0r'

decrypted = bytes([data[i] ^ key[i % 36] for i in range(len(data))])

with open('decrypted.png', 'wb') as f:
    f.write(decrypted)
```

```bash
$ file decrypted.png
decrypted.png: PNG image data, 1024 x 1024, 8-bit/color RGBA, non-interlaced
```

---

## Paso 4: Obtención de la Flag

Al visualizar la imagen `decrypted.png`, vemos:

- **Santa Claus** (Viejo Pascuero) en un laboratorio de ciberseguridad
- Título: "NORTH POLE CYBERSECURITY LAB - Naughty List Division"
- **Flag visible en la parte inferior de la imagen**

![Decrypted PNG](decrypted.png)

### Verificación con el ejecutable

```
C:\> main.exe
password: th1s_1s_th3_passw0rd_u_r_l00k1ng_f0r
[+] You got the flag.. but where is it??!
```

El programa confirma que la contraseña es correcta y nos indica que la flag está "en algún lugar" - efectivamente está embebida en la imagen PNG descifrada.

---

## Flag

```
3l_vi3j1t0_p4scu3ro!@malwarespace.com
```

**Traducción:** "El Viejito Pascuero" (nombre chileno para Santa Claus) escrito en leetspeak.

---

## Resumen de la Solución

```
┌─────────────────────────────────────────────────────────────────┐
│                        main.exe                                  │
│                           │                                      │
│                           ▼                                      │
│              ┌────────────────────────┐                         │
│              │   RCDATA/101 (2.1MB)   │                         │
│              │   [PNG cifrado XOR]    │                         │
│              └────────────────────────┘                         │
│                           │                                      │
│                           ▼                                      │
│     ┌─────────────────────────────────────────────┐             │
│     │  Derivar clave usando estructura PNG:       │             │
│     │  - PNG header → "th1s_1s_"                  │             │
│     │  - IHDR chunk → "th3_pass"                  │             │
│     │  - sRGB/gAMA/pHYs → completar 36 chars      │             │
│     └─────────────────────────────────────────────┘             │
│                           │                                      │
│                           ▼                                      │
│        Key: th1s_1s_th3_passw0rd_u_r_l00k1ng_f0r                │
│                           │                                      │
│                           ▼                                      │
│              ┌────────────────────────┐                         │
│              │    decrypted.png       │                         │
│              │    (1024x1024 RGBA)    │                         │
│              └────────────────────────┘                         │
│                           │                                      │
│                           ▼                                      │
│        FLAG: 3l_vi3j1t0_p4scu3ro!@malwarespace.com             │
└─────────────────────────────────────────────────────────────────┘
```

---

## Herramientas Utilizadas

- `file` - Identificación de tipos de archivo
- `strings` - Extracción de strings del binario
- `7z` - Extracción de recursos del PE
- `xxd` - Visualización hexadecimal
- `exiftool` - Análisis de metadata
- `Python 3` - Scripts de descifrado XOR

---

## Lecciones Aprendidas

1. **Conocer estructuras de archivos:** La estructura bien definida de PNG permitió derivar la clave XOR byte a byte.

2. **XOR es reversible:** Si conocemos parte del plaintext esperado, podemos derivar la clave.

3. **Recursos embebidos:** Los ejecutables PE pueden contener recursos que son el verdadero objetivo del análisis.

4. **Múltiples capas:** El reto requirió primero encontrar la contraseña del programa para luego descubrir que la flag estaba en la imagen descifrada.

---

## Scripts de Solución

### solve_final.py

```python
#!/usr/bin/env python3
"""
Solución completa para el reto "Viejo Pascuero" - Malwarespace CTF 2025
"""

def extract_and_decrypt():
    # Leer el recurso extraído
    with open('resources/101', 'rb') as f:
        data = f.read()

    # Clave derivada de la estructura PNG
    key = b'th1s_1s_th3_passw0rd_u_r_l00k1ng_f0r'

    # Descifrar con XOR
    decrypted = bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

    # Guardar PNG
    with open('decrypted.png', 'wb') as f:
        f.write(decrypted)

    print(f'[+] PNG descifrado guardado en decrypted.png')
    print(f'[+] Password para main.exe: {key.decode()}')
    print(f'[+] Flag: 3l_vi3j1t0_p4scu3ro!@malwarespace.com')

if __name__ == '__main__':
    extract_and_decrypt()
```

---

**Autor:** p0mb3r0
**Fecha:** 10 de Diciembre de 2025
**CTF:** Malwarespace 2025
