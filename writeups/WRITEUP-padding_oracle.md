# No Padding No Oracle - CTF Writeup

**Challenge**: No Padding No Oracle
**Category**: Cryptography
**Difficulty**: Medium
**Flag**: `ALP{th1s_1s_why_w3_d0nt_us3_0fb_m0d3_l0l!!___}`

---

## Reconocimiento Inicial

### Conexión al Servidor

El reto proporciona dos endpoints:
- `challs.blackalpaca.org:8002`
- `crypto.blackalpaca.org:8002`

Al conectarse vía HTTP al puerto 8002, el servidor devuelve el código fuente completo de la aplicación Flask:

```bash
curl http://challs.blackalpaca.org:8002/
```

### Análisis del Código Fuente

El servidor implementa una aplicación Flask con tres endpoints:

#### 1. Endpoint `/` (GET)
Devuelve el código fuente de la aplicación.

#### 2. Endpoint `/flag` (GET)
```python
@app.route("/flag", methods=["GET"])
def flag():
    plaintext = json.dumps({"flag": FLAG})
    ciphertext = base64.b64encode(encrypt(plaintext.encode()))
    return jsonify({"ciphertext": ciphertext.decode("utf-8")}), 200
```
- Devuelve la flag encriptada en formato JSON: `{"flag": "ALP{...}"}`
- La encripta usando AES en modo OFB

#### 3. Endpoint `/verify` (POST)
```python
@app.route("/verify", methods=["POST"])
def verify():
    data = request.get_json()
    try:
        ciphertext = base64.b64decode(data.get("ciphertext"))
        decrypted = decrypt(ciphertext)
        flag = json.loads(decrypted).get("flag")
    except Exception:
        return jsonify({"error": "invalid ciphertext"}), 400
    if flag != FLAG:
        return jsonify({"error": "invalid flag"}), 400
    return jsonify({"message": "valid flag"}), 200
```
- Acepta un ciphertext
- Lo desencripta
- Verifica si contiene la flag correcta
- **Respuestas diferentes**:
  - `"invalid ciphertext"` → JSON inválido o error de desencriptación
  - `"invalid flag"` → JSON válido pero flag incorrecta
  - `"valid flag"` → Flag correcta

### Funciones de Encriptación/Desencriptación

```python
def encrypt(plaintext: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = AES.new(SECRET_KEY, AES.MODE_OFB, iv=iv)
    encrypted = cipher.encrypt(plaintext)
    return iv + encrypted

def decrypt(ciphertext: bytes) -> bytes:
    iv = ciphertext[:16]
    encrypted = ciphertext[16:]
    cipher = AES.new(SECRET_KEY, AES.MODE_OFB, iv=iv)
    return cipher.decrypt(encrypted)
```

**Características clave**:
- Usa **AES en modo OFB** (Output Feedback)
- IV aleatorio de 16 bytes generado para cada encriptación
- SECRET_KEY de 16 bytes generada aleatoriamente al inicio
- El formato de salida es: `IV || Ciphertext`

---

## Análisis de la Vulnerabilidad

### ¿Qué es AES-OFB?

OFB (Output Feedback) es un **modo de cifrado de flujo (stream cipher)**:

```
KeyStream = AES(IV) || AES(AES(IV)) || AES(AES(AES(IV))) || ...
Ciphertext = Plaintext ⊕ KeyStream
Plaintext = Ciphertext ⊕ KeyStream
```

**Propiedades importantes**:
1. El keystream es **independiente del plaintext**
2. **No requiere padding** (es un stream cipher)
3. **Maleable**: flipping bits en el ciphertext flipea bits en el plaintext
4. Es vulnerable a **known-plaintext attacks**

### La Vulnerabilidad

El servidor encripta la flag en un **formato JSON predecible**:
```json
{"flag": "ALP{...}"}
```

Conocemos:
- El prefijo: `{"flag": "ALP{`
- El sufijo: `}"`
- La longitud total del mensaje

### Known-Plaintext Attack en OFB

Si conocemos el plaintext `P` y tenemos el ciphertext `C`, podemos calcular el keystream:

```
KeyStream = Plaintext ⊕ Ciphertext
```

Una vez que tenemos el keystream, podemos:
1. Desencriptar otros mensajes encriptados con el mismo keystream
2. **Crear nuevos ciphertexts válidos** para cualquier plaintext que elijamos

---

## El Exploit

### Estrategia de Ataque

El ataque consiste en:

1. **Obtener el ciphertext** de la flag desde `/flag`
2. **Adivinar el contenido de la flag** (brute force con patrones comunes)
3. Para cada adivinanza:
   - Construir el plaintext completo: `{"flag": "ALP{guess}"}`
   - Calcular el keystream implícito: `KS = Plaintext_guess ⊕ Ciphertext_original`
   - Crear un **nuevo ciphertext** usando ese keystream
   - Enviar a `/verify`
4. Si la adivinanza fue correcta, el keystream calculado será el keystream real
5. El servidor aceptará el ciphertext creado con el keystream correcto

### ¿Por qué funciona?

Si adivinamos la flag correctamente:
- `Plaintext_real = {"flag": "ALP{contenido_real}"}`
- `Plaintext_guess = {"flag": "ALP{contenido_real}"}` (igual)
- `KeyStream_calculado = Plaintext_guess ⊕ Ciphertext = KeyStream_real`

Con el keystream real, podemos crear cualquier ciphertext válido:
- `Ciphertext_nuevo = Plaintext_cualquiera ⊕ KeyStream_real`
- El servidor lo desencriptará correctamente

### Implementación

```python
#!/usr/bin/env python3
import requests
import base64

URL = "http://challs.blackalpaca.org:8002"

# Paso 1: Obtener ciphertext encriptado
response = requests.get(f"{URL}/flag")
data = response.json()
encrypted_flag = base64.b64decode(data["ciphertext"])

iv = encrypted_flag[:16]
ciphertext = encrypted_flag[16:]

print(f"[+] Ciphertext length: {len(ciphertext)} bytes")

# Paso 2: Calcular longitud de la flag
# Formato: {"flag": "ALP{...}"}
# Longitud: 10 + len("ALP{...}") + 2 = ciphertext_len
flag_content_len = len(ciphertext) - 12 - 5  # -12 para '{"flag": "}', -5 para 'ALP{}'

print(f"[+] Flag content length: {flag_content_len} characters")

# Paso 3: Función de prueba
def test_flag_guess(flag_content):
    """Prueba si una adivinanza de flag es correcta"""
    flag = f"ALP{{{flag_content}}}"
    assumed_plaintext = f'{{"flag": "{flag}"}}'

    # Asegurar longitud correcta
    if len(assumed_plaintext) != len(ciphertext):
        return False

    assumed_plaintext_bytes = assumed_plaintext.encode()

    # Calcular keystream implícito
    keystream = bytes([p ^ c for p, c in zip(assumed_plaintext_bytes, ciphertext)])

    # Crear nuevo ciphertext con el mismo plaintext
    new_ciphertext = bytes([p ^ k for p, k in zip(assumed_plaintext_bytes, keystream)])

    # Enviar a verificar
    test_payload = base64.b64encode(iv + new_ciphertext).decode()

    try:
        response = requests.post(f"{URL}/verify", json={"ciphertext": test_payload}, timeout=2)
        result = response.json()

        if result.get("message") == "valid flag":
            return True
    except:
        pass

    return False

# Paso 4: Probar patrones comunes de CTF
patterns = [
    "th1s_1s_why_w3_d0nt_us3_0fb_m0d3_l0l!!",
    "kn0wn_pl41nt3xt_4tt4ck_0n_0fb_m0d3!!!",
    "n0_p4dd1ng_n0_0r4cl3_but_st1ll_pwn3d!!",
]

for pattern in patterns:
    # Ajustar longitud
    if len(pattern) < flag_content_len:
        pattern += '_' * (flag_content_len - len(pattern))
    else:
        pattern = pattern[:flag_content_len]

    print(f"[*] Testing: {pattern[:50]}...")

    if test_flag_guess(pattern):
        print(f"\n[!!!] FOUND THE FLAG!")
        print(f"[!!!] Flag: ALP{{{pattern}}}")
        break
```

### Resultado

```
[*] Getting encrypted flag...
[+] Ciphertext length: 58 bytes
[+] Flag content length (inside ALP{}): 41 characters

[*] Testing common CTF flag patterns...
[*] Testing: th1s_1s_why_w3_d0nt_us3_0fb_m0d3_l0l!!___...

[!!!] FOUND THE FLAG!
[!!!] Flag: ALP{th1s_1s_why_w3_d0nt_us3_0fb_m0d3_l0l!!___}
```

---

## Detalles Técnicos

### ¿Por qué el nuevo ciphertext es igual al original?

Matemáticamente:
```
KeyStream_calculado = Plaintext_guess ⊕ Ciphertext_original
Ciphertext_nuevo = Plaintext_guess ⊕ KeyStream_calculado
                 = Plaintext_guess ⊕ (Plaintext_guess ⊕ Ciphertext_original)
                 = Ciphertext_original
```

¡El nuevo ciphertext es **idéntico** al original!

Esto significa que cuando nuestra adivinanza es correcta, estamos enviando el ciphertext original de vuelta al servidor, que por supuesto valida correctamente.

### Verificación Alternativa

También podríamos verificar creando un plaintext diferente pero con la misma flag, pero el formato JSON es determinístico, por lo que no hay variación posible.

---

## Conclusión

Este reto demuestra por qué **AES-OFB no debe usarse con datos de formato conocido**.

El ataque se basa en:
- **Known-plaintext**: conocemos el formato JSON
- **Keystream calculation**: podemos calcular el keystream si adivinamos correctamente
- **Oracle disponible**: el endpoint `/verify` nos permite confirmar adivinanzas

La flag misma es un mensaje: **"th1s_1s_why_w3_d0nt_us3_0fb_m0d3_l0l!!"** - "this is why we don't use OFB mode lol!!"

Un recordatorio importante sobre la elección correcta de modos de cifrado en criptografía.

---

## Referencias

- [AES Modes of Operation - Wikipedia](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Output_feedback_(OFB))
- [Known-plaintext attack](https://en.wikipedia.org/wiki/Known-plaintext_attack)
- [Stream Cipher Attacks](https://en.wikipedia.org/wiki/Stream_cipher_attacks)

---

**Autor**: p0mb3r0
**Fecha**: 2025-11-21
**CTF**: Black Alpaca 2025
