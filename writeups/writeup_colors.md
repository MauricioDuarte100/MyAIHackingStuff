# Writeup: Reto CTF "Colors" - MalwareSpace 2025

## Descripción del Reto
Se nos entrega un archivo HTML llamado `challenge.html` que contiene una gran cantidad de clases CSS definiendo colores de fondo (`background-color`) y un script de JavaScript que asigna estas clases aleatoriamente a elementos `div`. El enunciado sugiere que hay algo escondido en estos colores.

## Paso 1: Reconocimiento y Extracción

Al inspeccionar `challenge.html`, notamos dos componentes clave:
1.  **CSS:** Miles de clases con nombres aleatorios, cada una definiendo un color hexadecimal (ej. `.abc { background-color: #414243; }`).
2.  **JavaScript:** Un array gigante llamado `classes` que contiene los nombres de estas clases en un orden específico.

La hipótesis es que los colores hexadecimales representan bytes de un archivo binario. Cada color `#RRGGBB` contiene 3 bytes.

Creamos un script en Python para parsear el HTML, mapear las clases a sus colores y reconstruir el binario siguiendo el orden del array de JavaScript.

```python
import re

def extract_payload():
    with open('challenge.html', 'r') as f:
        content = f.read()

    # 1. Extraer definiciones CSS (.nombre { background-color: #HEX; })
    css_pattern = re.compile(r'\.([a-zA-Z0-9]+)\s*{\s*background-color:\s*(#[0-9a-fA-F]{6});\s*}')
    css_matches = css_pattern.findall(content)
    class_to_color = {name: color for name, color in css_matches}

    # 2. Extraer el array de JavaScript para saber el orden
    js_pattern = re.compile(r"const classes = \[(.*?)\];", re.DOTALL)
    js_match = js_pattern.search(content)
    js_content = js_match.group(1)
    # Limpiar comillas y espacios
    classes_list = [c.strip().strip("'").strip('"') for c in js_content.split(',')]

    # 3. Reconstruir los bytes
    bytes_data = bytearray()
    for c in classes_list:
        if c in class_to_color:
            color = class_to_color[c] # ej: #1a2b3c
            r = int(color[1:3], 16)
            g = int(color[3:5], 16)
            b = int(color[5:7], 16)
            bytes_data.extend([r, g, b])

    with open('output.bin', 'wb') as f:
        f.write(bytes_data)
    print("Payload extraído en output.bin")

if __name__ == '__main__':
    extract_payload()
```

## Paso 2: Análisis del Shellcode

El archivo resultante `output.bin` es identificado como **data**, pero al analizar los primeros bytes y desensamblarlo, se confirma que es **Shellcode para Windows x64**.

### Strings en la Pila (Stack Strings)
Al usar el comando `strings` estándar, no se veían muchas cadenas ótiles. Esto es porque el shellcode utiliza una técnica comón de ofuscación donde construye las cadenas byte por byte en la pila (`MOV BYTE PTR [RSP+offset], char`) antes de llamar a las funciones.

Analizando el desensamblado, identificamos la construcción de las siguientes cadenas:
*   `KERNEL32.DLL`
*   `GetProcAddress`
*   `LoadLibraryA`
*   `advapi32.dll`
*   `CryptAcquireContextA`
*   `CryptCreateHash`, `CryptHashData`, `CryptDeriveKey`, `CryptDecrypt`
*   `flag.txt`

Esto indica claramente que el shellcode intenta descifrar algo.

## Paso 3: Criptografía y La Clave

El flujo del shellcode mostraba el siguiente comportamiento:
1.  Carga librerías criptográficas.
2.  Toma un valor de 4 bytes.
3.  Calcula el hash **SHA-256** de ese valor.
4.  Usa el hash resultante como clave para **AES-256**.
5.  Descifra un blob de datos incrustado en el propio shellcode.

### Encontrando la "Semilla"
El valor de 4 bytes no estaba explícito en el código como una constante obvia, pero revisando el archivo `challenge.html` original nuevamente, encontramos un comentario sospechoso al inicio:

```html
<!-- Compiled at GMT: Sunday, 16 March 2025 9:34:37 -->
```

Convertimos esa fecha a un Timestamp Unix (Epoch):
*   Fecha: `Sunday, 16 March 2025 9:34:37 GMT`
*   Timestamp: `1742117677`
*   Hexadecimal (Little Endian): `2d 9b d6 67`

## Paso 4: Descifrado y Flag

Con la marca de tiempo como semilla, procedemos a replicar el proceso de descifrado.

1.  **Extraer el Blob cifrado:** Identificamos los bytes cifrados dentro del shellcode (en el offset donde se realizaba la llamada a `CryptDecrypt`).
2.  **Derivar la clave:**
    *   Input: `1742117677` (como bytes little-endian: `\x2d\x9b\xd6\x67`).
    *   Algoritmo: SHA-256.
    *   Clave resultante: `820a2cf6e0a71338e16cb15469f9726b5cd830dee6a12fffec3f0d6d89f42211`

3.  **Descifrar:**
    Usamos `openssl` (asumiendo AES-256-CBC y un IV de ceros, comón en implementaciones simples de `CryptDeriveKey` de Windows si no se especifica sal).

```bash
# Blob extraído a blob.bin
openssl enc -aes-256-cbc -d \
    -K 820a2cf6e0a71338e16cb15469f9726b5cd830dee6a12fffec3f0d6d89f42211 \
    -iv 00000000000000000000000000000000 \
    -in blob.bin -out decrypted.txt
```

### Resultado
Al leer el archivo `decrypted.txt`, obtenemos la flag en texto plano:

**Flag:** `xm4s_r3v3rs1ng_th3_gr1nch_sh3llc0d3@malwarespace.com`

```