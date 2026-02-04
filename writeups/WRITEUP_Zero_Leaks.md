# Zero Leaks - CTF Writeup

**Challenge**: Zero Leaks
**Category**: Cryptography
**Server**: challs.blackalpaca.org:8004
**Flag**: `ALP{n3v3r_7ru57_4_5y573m_y0u_c4nn07_br34k}`

---

## Reconocimiento Inicial

### Conexión al servidor

Primero intenté conectarme al servidor usando `netcat`, pero no obtuve respuesta inicial:

```bash
nc challs.blackalpaca.org 8004
```

No hubo banner ni menú visible. Probé varios comandos básicos sin éxito.

### Descubrimiento del protocolo HTTP

Al enviar comandos arbitrarios como "encrypt", el servidor respondió con un error HTTP 500:

```
HTTP/1.1 500 Internal Server Error
Connection: close
Content-Type: text/html
Content-Length: 141
```

Esto reveló que el servidor usa HTTP, no un protocolo de texto plano.

---

## Análisis del Código Fuente

Hice una petición HTTP GET a la raíz del servidor:

```bash
GET / HTTP/1.1
Host: challs.blackalpaca.org
```

El servidor devolvió su propio código fuente (Flask application):

```python
import os
from flask import Flask, request, jsonify
from Crypto.Cipher import AES

FLAG = os.getenv("FLAG", "ALP{dummy}")
SECRET_KEY = os.urandom(16)

app = Flask(__name__)

def _encrypt(plaintext: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = AES.new(SECRET_KEY, AES.MODE_OFB, iv=iv)
    encrypted = cipher.encrypt(plaintext)
    return iv + encrypted

def _decrypt(ciphertext: bytes) -> bytes:
    iv = ciphertext[:16]
    encrypted = ciphertext[16:]
    cipher = AES.new(SECRET_KEY, AES.MODE_OFB, iv=iv)
    return cipher.decrypt(encrypted)

def has_leaks(message: bytes) -> bool:
    return b"ALP{" in message

def randomize_position(plaintext: bytes) -> bytes:
    random_bytes = os.urandom(256 - len(plaintext))
    position = os.urandom(1)[0] % (257 - len(plaintext))
    return random_bytes[:position] + plaintext + random_bytes[position:]

@app.route("/flag", methods=["GET"])
def flag():
    plaintext = FLAG.encode("utf-8")
    plaintext = randomize_position(plaintext)
    ciphertext = _encrypt(plaintext)
    ciphertext_hex = ciphertext.hex()
    return jsonify({"flag_encrypted": ciphertext_hex}), 200

@app.route("/decrypt", methods=["POST"])
def decrypt():
    data = request.get_json()
    try:
        ciphertext_hex = data.get("ciphertext")
        ciphertext = bytes.fromhex(ciphertext_hex)
        plaintext = _decrypt(ciphertext)
        plaintext_hex = plaintext.hex()
    except Exception:
        return jsonify({"error": "invalid ciphertext"}), 400
    if has_leaks(plaintext):
        return jsonify({"error": "leak detected"}), 400
    return jsonify({"plaintext": plaintext_hex}), 200

@app.route("/encrypt", methods=["POST"])
def encrypt():
    data = request.get_json()
    try:
        plaintext_hex = data.get("plaintext")
        plaintext = bytes.fromhex(plaintext_hex)
        ciphertext = _encrypt(plaintext)
        ciphertext_hex = ciphertext.hex()
    except Exception:
        return jsonify({"error": "invalid plaintext"}), 400
    return jsonify({"ciphertext": ciphertext_hex}), 200
```

---

## Análisis de Vulnerabilidades

### Endpoints disponibles

1. **`GET /flag`**: Devuelve la flag cifrada con AES-OFB, insertada en una posición aleatoria dentro de 256 bytes aleatorios
2. **`POST /encrypt`**: Cifra un plaintext proporcionado por el usuario
3. **`POST /decrypt`**: Descifra un ciphertext, pero **rechaza** si el plaintext contiene `"ALP{"`

### Mecanismo de cifrado

- **Algoritmo**: AES en modo OFB (Output Feedback)
- **IV**: Generado aleatoriamente (16 bytes) y concatenado al ciphertext
- **Clave**: Generada aleatoriamente al iniciar el servidor

### La vulnerabilidad clave

El modo OFB tiene una propiedad matemática importante:

```
Ciphertext = Plaintext ⊕ KeyStream
Plaintext = Ciphertext ⊕ KeyStream
```

Donde `KeyStream` se genera a partir del IV y la clave secreta.

**Propiedad explotable**: Si modificamos el ciphertext con una máscara XOR:

```
Ciphertext' = Ciphertext ⊕ Mask
```

Entonces el plaintext resultante será:

```
Plaintext' = Plaintext ⊕ Mask
```

Esto significa que podemos "corromper" el plaintext de forma controlada sin conocer la clave.

---

## Estrategia de Ataque

### Concepto del exploit

1. Obtener la flag cifrada del endpoint `/flag`
2. Aplicar una máscara XOR al ciphertext para corromper el string `"ALP{"`
3. Enviar el ciphertext modificado al endpoint `/decrypt`
4. El servidor lo descifrará (pasará la validación porque ya no contiene `"ALP{"`)
5. Aplicar la misma máscara XOR al plaintext recibido para recuperar la flag original

### Diagrama del ataque

```
[Flag original] --AES-OFB--> [Ciphertext]
                                  |
                                  | XOR Mask
                                  v
                          [Ciphertext corrupto]
                                  |
                                  | /decrypt
                                  v
                          [Plaintext corrupto]
                                  |
                                  | XOR Mask (mismo)
                                  v
                          [Flag original] ✓
```

---

## Implementación del Exploit

### Código del exploit

```python
#!/usr/bin/env python3
import requests

BASE_URL = "http://challs.blackalpaca.org:8004"

def get_flag_encrypted():
    response = requests.get(f"{BASE_URL}/flag")
    data = response.json()
    return bytes.fromhex(data['flag_encrypted'])

def decrypt_ciphertext(ciphertext_hex):
    response = requests.post(f"{BASE_URL}/decrypt",
                            json={"ciphertext": ciphertext_hex},
                            headers={"Content-Type": "application/json"})
    return response

def xor_bytes(data, mask_byte):
    return bytes(b ^ mask_byte for b in data)

def exploit():
    # Obtener flag cifrada
    flag_ciphertext = get_flag_encrypted()

    # Separar IV y datos cifrados
    iv = flag_ciphertext[:16]
    ciphertext_data = flag_ciphertext[16:]

    # Aplicar máscara XOR (probamos con 0x01)
    mask = 0x01
    corrupted_data = xor_bytes(ciphertext_data, mask)
    corrupted_full = iv + corrupted_data

    # Enviar al servidor para descifrado
    response = decrypt_ciphertext(corrupted_full.hex())

    if response.status_code == 200:
        data = response.json()
        corrupted_plaintext = bytes.fromhex(data['plaintext'])

        # Recuperar plaintext original
        original_plaintext = xor_bytes(corrupted_plaintext, mask)

        # Buscar la flag
        if b"ALP{" in original_plaintext:
            start = original_plaintext.index(b"ALP{")
            end = original_plaintext.index(b"}", start) + 1
            flag = original_plaintext[start:end]
            print(f"FLAG: {flag.decode()}")
            return flag.decode()

if __name__ == "__main__":
    exploit()
```

### Ejecución

```bash
python3 exploit_v2.py
```

### Resultado

```
[*] Obteniendo flag cifrada...
[+] Flag cifrada recibida (len=272)
[*] IV: ee7cb9e96f54a933fe391937662391e2
[*] Ciphertext data (len=256): 30054a926939f33bf94e51020defc12a...

[*] Probando con máscara: 0x01

[+] FLAG ENCONTRADA: ALP{n3v3r_7ru57_4_5y573m_y0u_c4nn07_br34k}
```

---

## Flag

```
ALP{n3v3r_7ru57_4_5y573m_y0u_c4nn07_br34k}
```

---

## Lecciones Aprendidas

### Vulnerabilidades identificadas

1. **Leak del código fuente**: El servidor expone su implementación completa en el endpoint raíz
2. **Modo de cifrado inseguro**: OFB permite manipulación maleable del ciphertext
3. **Validación inadecuada**: La detección de "leaks" se hace después del descifrado, no antes

### Mitigaciones recomendadas

1. **Usar modos autenticados**: AES-GCM o ChaCha20-Poly1305 proporcionan autenticación
2. **No exponer el código fuente** en producción
3. **Implementar rate limiting** para prevenir ataques automatizados
4. **Usar HMAC** para verificar la integridad del ciphertext antes de descifrarlo

### Conceptos criptográficos clave

- **Maleabilidad**: Propiedad de algunos cifrados donde modificar el ciphertext produce cambios predecibles en el plaintext
- **OFB Mode**: Convierte un cifrado de bloques en un cifrado de flujo, pero es maleable
- **XOR properties**: `(A ⊕ B) ⊕ B = A` (propiedad de auto-inversión)

---

## Referencias

- [AES Modes of Operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Output_feedback_(OFB))
- [Cryptographic Malleability](https://en.wikipedia.org/wiki/Malleability_(cryptography))
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)

---

**Author**: CTF Team
**Date**: 2025-11-21
