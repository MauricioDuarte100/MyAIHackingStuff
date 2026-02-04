# Kopitiam CTF Write-up

## Introducción
**Reto:** Kopitiam (Reverse Engineering)
**Objetivo:** Obtener la flag completando 3 niveles de "pedidos" de bebidas.
**Archivo:** `kopitiam` (ELF 64-bit LSB executable)

## Paso 1: Reconocimiento Inicial

Comenzamos identificando el tipo de archivo y buscando cadenas legibles.

```bash
file kopitiam
# Output: kopitiam: ELF 64-bit LSB pie executable...
```

Usando `strings` encontramos pistas sobre la estructura de niveles:
```bash
strings kopitiam | grep "Level"
# [Level 1] Enter order:
# [Level 2] Enter order:
# [Level 3] Enter order:
```

Ejecutamos el binario y vemos que nos pide inputs específicos con longitudes ocultas (*****, *******, **********).

## Paso 2: Nivel 1 (Lee)

Al analizar el código ensamblador (o usar `ltrace`), vemos una rutina de decodificación **Morse** seguida de una codificación **Base32**.

1.  **Lógica:** Input -> Morse -> Base32 -> Comparación.
2.  **Cadena Objetivo (Base32):** Se encuentra en la memoria o en el binario (`strings` ayuda aquí).
    *   Cadena: `FUXC2IBNFUWSALRNFUXCALROEAWS2LJNFU======`
3.  **Solución:** Decodificar Base32 a Morse y luego Morse a Texto.

### Script Solver (Nivel 1)
```python
import base64

# Cadena extraída del binario
b32 = "FUXC2IBNFUWSALRNFUXCALROEAWS2LJNFU======"

# Decodificamos Base32
decoded_bytes = base64.b32decode(b32)
# Resultado: b'-.- --- .--. .. -----'
print(f"Morse: {decoded_bytes.decode()}")

# Morse '-.- --- .--. .. -----' se traduce a:
# -.-  = K
# ---  = O
# .--. = P
# ..   = I
# -----= 0
print("Password Nivel 1: kopi0")
```

**Password Nivel 1:** `kopi0`

---

## Paso 3: Nivel 2 (Ali)

El segundo nivel utiliza una codificación **Base58** personalizada y una operación **XOR**.

1.  **Lógica:** Input -> XOR ("SG") -> Base58 -> Comparación.
2.  **Alfabeto Base58:** Encontramos un alfabeto no estándar en el binario:
    `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`
3.  **Cadena Objetivo:** `2V1ncHsTCX`
4.  **Solución:** Decodificar Base58 (usando el alfabeto custom) y luego hacer XOR con la clave "SG".

### Script Solver (Nivel 2)
```python
# Alfabeto encontrado en el binario (offset 0x36ac00)
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def b58decode(s):
    n = 0
    for c in s:
        n = n * 58 + ALPHABET.index(c)
    res = []
    while n > 0:
        n, mod = divmod(n, 256)
        res.append(mod)
    return bytes(reversed(res))

target = "2V1ncHsTCX"
decoded = b58decode(target) # Bytes sin XOR

# XOR con clave "SG"
key = b"SG"
result = []
for i in range(len(decoded)):
    result.append(decoded[i] ^ key[i % len(key)])

print(f"Password Nivel 2: {bytes(result).decode()}")
# Resultado: tehP3ng
```

**Password Nivel 2:** `tehP3ng`

---

## Paso 4: Nivel 3 (Sotong)

El tercer nivel verifica la longitud (10 caracteres) y aplica un cifrado de sustitución aritmética basado en si la letra es mayúscula o minúscula.

1.  **Lógica:**
    *   Si es minúscula: `((char - 84) % 26) + 97 + 3`
    *   Si es mayúscula: `((char - 52) % 26) + 65 + 3`
2.  **Target Bytes:** `7b 65 66 79 5b 65 69 65 64 77` -> `"{efy[eiedw"`
3.  **Solución:** Brute-force inverso (probar caracteres imprimibles hasta que coincidan con la transformación).

### Script Solver (Nivel 3)
```python
import string

target_str = "{efy[eiedw"
charset = string.ascii_letters
password = ""

for t_char in target_str:
    target_val = ord(t_char)
    for c in charset:
        val = ord(c)
        if 'a' <= c <= 'z':
            transformed = ((val - 84) % 26) + 97 + 3
        else:
            transformed = ((val - 52) % 26) + 65 + 3
        
        if transformed == target_val:
            password += c
            break

print(f"Password Nivel 3: {password}")
# Resultado: kopiKosong
```

**Password Nivel 3:** `kopiKosong`

---

## Resultado Final

Al ejecutar el binario e introducir las 3 contraseñas secuencialmente:

1.  `kopi0`
2.  `tehP3ng`
3.  `kopiKosong`

El programa descifra la flag final.

**Flag:** `YBN25{TR3AT_Y0U_LIM_K0PI}`
