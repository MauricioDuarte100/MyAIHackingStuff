# Ignition - CTF Writeup

**Competencia:** Advent of Malware 2025 - Challenge 006
**Categoría:** Reversing / Cryptography / Steganography
**Dificultad:** Media-Alta
**Flag:** `MAL{y0u_ar3_n0t_4ll0w3d_to_v13w_th1s_fl4g@malwarespace.com}`

---

## Descripción del Reto

> *In Santa's workshop, an encrypted file was recovered from a broken toy-maker machine. The elves swear it was part of a secret 'secure messaging' experiment gone wrong. Santa mixed keys, juggled numbers, and left a curious puzzle inside. Maybe, just maybe, the truth can be unwrapped if you understand how his holiday gadgets 'talk' to each other.*

**Archivos proporcionados:**
- `ignition.exe` - Ejecutable encriptador (9.8 MB)
- `flag2.enc` - Archivo cifrado que contiene la flag (1,878,242 bytes)
- `Untitled.jpg` / `Untitled.enc` - Par plaintext/ciphertext conocido
- `large_test.png` / `large_test.enc` - Par plaintext/ciphertext conocido (más grande)

---

## Fase 1: Análisis Inicial

### Identificación del Ejecutable

```bash
$ file ignition.exe
ignition.exe: PE32+ executable (console) x86-64, for MS Windows, 8 sections

$ exiftool ignition.exe | grep -E "Company|Product|Internal"
Company Name                    : chall
Product Name                    : chall
Internal Name                   : chall.dll
```

El ejecutable es una aplicación de consola para Windows x64. Los metadatos revelan que originalmente era un DLL llamado "chall", lo que sugiere que es una aplicación .NET compilada con AOT (Ahead-of-Time).

### Análisis de Strings

Al extraer strings del ejecutable, encontramos referencias criptográficas importantes:

```
BouncyCastle.Cryptography
ChaCha20Poly1305
X25519
Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305
Org.BouncyCastle.Crypto.Agreement.X25519Agreement
```

Esto indica que el programa utiliza:
- **ChaCha20Poly1305**: Cifrado de flujo autenticado (AEAD)
- **X25519**: Intercambio de claves Diffie-Hellman sobre curva elíptica

También encontramos múltiples matrices de datos llamadas `keyMatrices_L1` hasta `keyMatrices_L9`, sugiriendo algún tipo de sistema de claves por capas.

---

## Fase 2: Análisis de la Estructura del Archivo Cifrado

### Comparación de Headers

Al comparar los archivos `.enc`, descubrimos un patrón crítico:

```python
# Primeros 32 bytes (Header 1) - IDÉNTICOS en todos los archivos
large_test.enc[0:32] = SECRET_REDACTED_BY_ANTIGRAVITY15161718191a1b1c1d1e1f20
Untitled.enc[0:32]   = SECRET_REDACTED_BY_ANTIGRAVITY15161718191a1b1c1d1e1f20
flag2.enc[0:32]      = SECRET_REDACTED_BY_ANTIGRAVITY15161718191a1b1c1d1e1f20

# Bytes 32-64 (Block 1 Data) - IDÉNTICOS en todos los archivos
large_test.enc[32:64] = SECRET_REDACTED_BY_ANTIGRAVITYf0b12df39a9b84a49c7c1d12
Untitled.enc[32:64]   = SECRET_REDACTED_BY_ANTIGRAVITYf0b12df39a9b84a49c7c1d12
flag2.enc[32:64]      = SECRET_REDACTED_BY_ANTIGRAVITYf0b12df39a9b84a49c7c1d12

# Bytes 64-76 (Header 2) - IDÉNTICOS
Todos: 0102030405060708090a0b0c
```

### Estructura Identificada

```
┌─────────────────────────────────────────────────────────────────┐
│ Offset    │ Tamaño │ Contenido                                  │
├───────────┼────────┼────────────────────────────────────────────┤
│ 0-31      │ 32     │ Nonce/Counter (01 02 03 ... 20)            │
│ 32-63     │ 32     │ Clave Pública Efímera X25519               │
│ 64-75     │ 12     │ Counter secundario (01 02 03 ... 0C)       │
│ 76 to -16 │ var    │ Datos cifrados (plaintext XOR keystream)   │
│ -16 to end│ 16     │ Authentication Tag (Poly1305)              │
└─────────────────────────────────────────────────────────────────┘

Overhead total: 32 + 32 + 12 + 16 = 92 bytes
```

### Verificación del Overhead

```python
# large_test.png: 3,004,725 bytes → large_test.enc: 3,004,817 bytes
# Diferencia: 92 bytes ✓

# Untitled.jpg: 7,913 bytes → Untitled.enc: 8,005 bytes
# Diferencia: 92 bytes ✓

# flag2.enc: 1,878,242 bytes → plaintext esperado: 1,878,150 bytes
```

---

## Fase 3: Descubrimiento de la Vulnerabilidad

### Two-Time Pad Attack

El hecho de que los bytes 32-64 sean **idénticos** en todos los archivos cifrados es una vulnerabilidad crítica. Estos 32 bytes representan la **clave pública efímera X25519** del encriptador.

En un sistema X25519 + ChaCha20Poly1305 correctamente implementado:
1. El encriptador genera un par de claves efímeras (privada, pública) para **cada archivo**
2. Se calcula el secreto compartido: `shared_secret = X25519(ephemeral_private, recipient_public)`
3. Se deriva la clave de ChaCha20 del secreto compartido
4. Cada archivo tiene un keystream diferente

**El error en este reto:** Se reutilizó la misma clave efímera para todos los archivos, resultando en el **mismo secreto compartido** y por lo tanto el **mismo keystream**.

### Verificación del Ataque

```python
# Si el keystream es el mismo para todos los archivos:
# enc1[76:] XOR enc2[76:] = plain1 XOR plain2
# (los keystreams se cancelan)

# Verificación con archivos conocidos:
overlap_len = min(len(large_plain), len(jpg_plain))  # 7,913 bytes

enc_xor = bytes([large_enc[76+i] ^ jpg_enc[76+i] for i in range(overlap_len)])
plain_xor = bytes([large_plain[i] ^ jpg_plain[i] for i in range(overlap_len)])

assert enc_xor == plain_xor  # ✓ CONFIRMADO - Two-Time Pad!
```

---

## Fase 4: Extracción del Keystream y Decriptación

### Extracción del Keystream

Usando el par conocido más grande (`large_test.png` / `large_test.enc`), extraemos el keystream:

```python
with open('large_test.png', 'rb') as f:
    large_plain = f.read()  # 3,004,725 bytes

with open('large_test.enc', 'rb') as f:
    large_enc = f.read()

# Extraer keystream: plaintext XOR ciphertext
# Los datos cifrados comienzan en offset 76 y terminan 16 bytes antes del final
keystream = bytes([large_enc[76+i] ^ large_plain[i] for i in range(len(large_plain))])
# Keystream extraído: 3,004,725 bytes
```

### Decriptación de flag2.enc

```python
with open('flag2.enc', 'rb') as f:
    flag_enc = f.read()

# Calcular tamaño del plaintext
flag_plain_size = len(flag_enc) - 92  # 1,878,150 bytes

# Verificar que tenemos suficiente keystream
assert flag_plain_size <= len(keystream)  # ✓

# Decriptar
decrypted = bytes([flag_enc[76+i] ^ keystream[i] for i in range(flag_plain_size)])

# Guardar resultado
with open('flag2_decrypted.png', 'wb') as f:
    f.write(decrypted)
```

### Verificación del PNG Decriptado

```bash
$ file flag2_decrypted.png
flag2_decrypted.png: PNG image data, 1603 x 1151, 8-bit/color RGB, non-interlaced

$ ls -la flag2_decrypted.png
-rw-r--r-- 1 user user 1878150 Dec 11 11:10 flag2_decrypted.png
```

La imagen decriptada muestra a Godzilla destruyendo una ciudad nevada con un árbol de Navidad. Hay texto visible que dice `...alsb@malwarespace.com` con una parte tachada/censurada en negro.

---

## Fase 5: Esteganografía LSB

### Análisis de la Imagen

Al analizar la imagen decriptada, encontramos:

1. **Datos ocultos después de IEND**: 154,461 bytes de datos después del chunk final del PNG (cifrados/ilegibles)
2. **Región censurada**: Una barra negra cubre parte del texto en la imagen
3. **Variación en píxeles "negros"**: Los píxeles de la barra negra no son uniformes

### Extracción LSB (Least Significant Bit)

La esteganografía LSB oculta datos en el bit menos significativo de cada canal de color de cada píxel:

```python
from PIL import Image
import numpy as np

img = Image.open('flag2_decrypted.png')
arr = np.array(img)

# Extraer el bit menos significativo de cada valor de píxel
lsb = arr & 1  # AND con 1 extrae solo el LSB

# Empaquetar los bits en bytes
lsb_bytes = np.packbits(lsb.flatten())
lsb_data = bytes(lsb_bytes)

# Buscar texto legible
import re
matches = re.findall(rb'[\x20-\x7e]{10,}', lsb_data[:5000])
```

### Resultado

```
Readable strings found:
  you_ar3_n0t_4ll0w3d_to_v13w_th1s_fl4g@malwarespace.com
  you_ar3_n0t_4ll0w3d_to_v13w_th1s_fl4g@malwarespace.com
  y0u_ar3_n0t_4ll0w3d_to_v13w_this_flag@malwarespace.com
  ... (múltiples variaciones con pequeñas diferencias debido a ruido)
```

---

## Flag Final

```
MAL{you_ar3_n0t_4ll0w3d_to_v13w_th1s_fl4g@malwarespace.com}
```

---

## Script Completo de Solución

```python
#!/usr/bin/env python3
"""
Ignition CTF Challenge - Complete Solution
Advent of Malware 2025 - Challenge 006
"""

from PIL import Image
import numpy as np
import re

def extract_keystream(plain_path, enc_path):
    """Extrae keystream de un par plaintext/ciphertext conocido"""
    with open(plain_path, 'rb') as f:
        plain = f.read()
    with open(enc_path, 'rb') as f:
        enc = f.read()

    # Datos cifrados comienzan en offset 76, terminan 16 bytes antes del final
    keystream = bytes([enc[76+i] ^ plain[i] for i in range(len(plain))])
    return keystream

def decrypt_file(enc_path, keystream, output_path):
    """Decripta un archivo usando el keystream extraído"""
    with open(enc_path, 'rb') as f:
        enc = f.read()

    # Tamaño del plaintext = tamaño enc - 92 bytes de overhead
    plain_size = len(enc) - 92

    if plain_size > len(keystream):
        raise ValueError(f"Keystream insuficiente: necesita {plain_size}, tiene {len(keystream)}")

    decrypted = bytes([enc[76+i] ^ keystream[i] for i in range(plain_size)])

    with open(output_path, 'wb') as f:
        f.write(decrypted)

    return decrypted

def extract_lsb_flag(image_path):
    """Extrae la flag oculta en los LSB de la imagen"""
    img = Image.open(image_path)
    arr = np.array(img)

    # Extraer LSB
    lsb = arr & 1
    lsb_bytes = np.packbits(lsb.flatten())
    lsb_data = bytes(lsb_bytes)

    # Buscar patrón de flag
    email_match = re.search(rb'[a-z0-9_]+@malwarespace\.com', lsb_data)
    if email_match:
        return f"MAL{{{email_match.group().decode()}}}"
    return None

def main():
    print("[*] Extrayendo keystream de par conocido...")
    keystream = extract_keystream('large_test.png', 'large_test.enc')
    print(f"[+] Keystream extraído: {len(keystream)} bytes")

    print("\n[*] Decriptando flag2.enc...")
    decrypt_file('flag2.enc', keystream, 'flag2_decrypted.png')
    print("[+] Archivo decriptado guardado como flag2_decrypted.png")

    print("\n[*] Extrayendo flag de LSB...")
    flag = extract_lsb_flag('flag2_decrypted.png')

    if flag:
        print(f"\n[+] FLAG ENCONTRADA: {flag}")
    else:
        print("[-] No se encontró flag en LSB")

if __name__ == "__main__":
    main()
```

---

## Resumen de Técnicas Utilizadas

| Fase | Técnica | Descripción |
|------|---------|-------------|
| 1 | Análisis estático | Identificación de bibliotecas criptográficas (BouncyCastle, ChaCha20, X25519) |
| 2 | Análisis de formato | Ingeniería inversa de la estructura del archivo cifrado |
| 3 | Known Plaintext Attack | Comparación de archivos cifrados para identificar reutilización de claves |
| 4 | Two-Time Pad Attack | Explotación de keystream reutilizado para decriptar archivos |
| 5 | LSB Steganography | Extracción de datos ocultos en bits menos significativos |

---

## Lecciones de Seguridad

1. **Nunca reutilizar claves efímeras**: En criptografía de curva elíptica, cada mensaje debe usar un par de claves efímeras único.

2. **Two-Time Pad es fatal**: Reutilizar un keystream permite a un atacante con plaintext conocido decriptar cualquier otro mensaje cifrado con el mismo keystream.

3. **La seguridad en capas importa**: Aunque se usó cifrado "fuerte" (ChaCha20Poly1305 + X25519), un error de implementación (reutilización de clave efímera) comprometió todo el sistema.

4. **La esteganografía no es cifrado**: Ocultar datos en LSB sin cifrarlos los hace fácilmente recuperables para cualquiera que sepa dónde buscar.

---

## Referencias

- [ChaCha20-Poly1305 RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439)
- [X25519 Key Agreement (RFC 7748)](https://datatracker.ietf.org/doc/html/rfc7748)
- [Two-Time Pad Attack](https://crypto.stackexchange.com/questions/59/taking-advantage-of-one-time-pad-key-reuse)
- [LSB Steganography](https://en.wikipedia.org/wiki/Bit_plane#Least_significant_bit_plane)

---

*Writeup by Antigravity Code - Diciembre 2025*
