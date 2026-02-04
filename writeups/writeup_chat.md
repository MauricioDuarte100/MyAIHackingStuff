# Chat CTF Challenge - Writeup

**CTF:** MalwareSpace 2025  
**Challenge:** Chat  
**Category:** Reversing  
**Flag:** `MWS{54nt4_r54_wr4pp3d_th3_k35tr34m_but_x0r_53t_1t_fr33_h0h0h0@malwarespace.com}`

---

## 📋 Enunciado

> An old chat log from a company attacked by malware was found recently. The company doesn't exist anymore, but some hints in this chat could help you figure out what happened.

Se nos proporciona un archivo `chat.json` con un registro de chat de una empresa.

---

## 🔍 Análisis Inicial

### Examinando el archivo JSON

El archivo `chat.json` contiene **289,893 mensajes** de un chat corporativo. Al examinar los primeros mensajes:

```json
{
    "name": "admin",
    "message": "From now the messages will be encrypted! Bye",
    "timestamp": 1765180688.191321
},
{
    "name": "admin", 
    "message": "SSBhbG1vc3QgZm9yZ290Lg==",
    "timestamp": 1765180688.1913226
}
```

Los mensajes están codificados en **Base64** a partir de cierto punto. Decodificando algunos:

| Base64 | Decodificado |
|--------|--------------|
| `SSBhbG1vc3QgZm9yZ290Lg==` | "I almost forgot." |
| `U2F5IGhlbGxvIHRvIHRoZSBuZXcgZW1wbG95ZWUuIENoYWQ=` | "Say hello to the new employee. Chad" |

### Descubriendo al intruso: Chad

Entre los mensajes, el usuario **Chad** envía algo diferente:

```json
{
    "name": "Chad",
    "message": "YmluYXJ5Og==",
    "timestamp": 1765180688.1913378
}
```

Decodificado: **"binary:"** - Chad anuncia que va a enviar un binario.

El siguiente mensaje de Chad:
```json
{
    "name": "Chad",
    "message": "f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAAwA1HAAAAAABAAAAAAAAAAJhaHAAAAAAAAAAAAEAAOAAGAEAAEAAPAAYAAAAEAAAAQAAAAAAAAABAAEAAAAAAAEAAQAAAAAAAUAEAAAAAAABQAQAAAAAAAAAQAAAAAAAABAAAAA==",
    "timestamp": 1765180688.1915672
}
```

Decodificando el Base64: `\x7fELF...` - ¡Es un **binario ELF**!

---

## 🛠️ Extracción del Binario

### Script de extracción

```python
import json
import base64

with open('chat.json', 'r') as f:
    data = json.load(f)

# Filtrar mensajes de Chad (sin los primeros 2: saludo y "binary:")
chad_messages = [msg for msg in data if msg['name'] == 'Chad']
print(f"Total mensajes de Chad: {len(chad_messages)}")  # 15,035

# Reconstruir el binario
binary_data = b''
for msg in chad_messages[2:]:  # Ignorar saludo y "binary:"
    decoded = base64.b64decode(msg['message'])
    binary_data += decoded

with open('malware.bin', 'wb') as f:
    f.write(binary_data)

print(f"Binario reconstruido: {len(binary_data)} bytes")  # 1,859,526 bytes
```

### Identificación del binario

```bash
$ file malware.bin
malware.bin: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), 
             statically linked, stripped
```

Es un binario **Go** compilado estáticamente (ransomware).

---

## 🔬 Análisis Estático del Malware

### Strings relevantes

```bash
$ strings malware.bin | grep -E "main\.|go_to_sleep"
main.generateRSAKeyPair
main.main
go_to_sleep/main.go
```

El malware se llama `go_to_sleep` y genera pares de claves RSA.

### Mensajes del ransomware

```
[+] RSA key pair generated in memory.
[+] Message A encrypted saved in: %s
[+] Message B encrypted saved in: %s
[+] XOR key encrypted (Keystream simulated) saved in: %s
[!] Failed to encrypt XOR key with RSA: %v
```

### Easter egg: Cita de Blade Runner

```
All those moments will be lost in time, like tears in rain. Time to die.
```

Esta cita de 72 caracteres es una pista crucial.

---

## 💾 Datos Embebidos al Final del ELF

Examinando los últimos bytes del binario:

```python
with open('malware.bin', 'rb') as f:
    data = f.read()

print(data[-500:])
```

Output:
```
cipher_a:<74 bytes encrypted>
cipher_b:<74 bytes encrypted>
enc_key:<128 bytes encrypted>
```

### Estructura de los datos

| Campo | Tamaño | Descripción |
|-------|--------|-------------|
| `cipher_a` | 74 bytes | Mensaje A cifrado con XOR |
| `cipher_b` | 74 bytes | Mensaje B cifrado con XOR |
| `enc_key` | 128 bytes | Clave XOR cifrada con RSA-1024 |

---

## 🎯 Ataque: XOR con Known-Plaintext

### La vulnerabilidad

Ambos mensajes fueron cifrados con la **misma clave XOR**:

```
cipher_a = plaintext_a ⊕ key
cipher_b = plaintext_b ⊕ key
```

Si conocemos uno de los plaintexts, podemos recuperar el otro:

```
cipher_a ⊕ cipher_b = plaintext_a ⊕ plaintext_b
```

### El plaintext conocido

La cita de Blade Runner tiene exactamente el largo correcto (72 bytes, los cipher tienen 74 bytes con padding):

```
"All those moments will be lost in time, like tears in rain. Time to die."
```

### Script de descifrado

```python
with open('malware.bin', 'rb') as f:
    data = f.read()

# Extraer datos cifrados
cipher_a_start = data.find(b'cipher_a:') + len(b'cipher_a:')
cipher_b_start = data.find(b'cipher_b:')
cipher_a = data[cipher_a_start:cipher_b_start]

cipher_b_start = data.find(b'cipher_b:') + len(b'cipher_b:')
enc_key_start = data.find(b'enc_key:')
cipher_b = data[cipher_b_start:enc_key_start]

# Known plaintext (la cita de Blade Runner)
blade_runner = b"All those moments will be lost in time, like tears in rain. Time to die."

# Recuperar la clave XOR usando cipher_a y el plaintext conocido
key = bytes(a ^ b for a, b in zip(cipher_a, blade_runner))

# Descifrar cipher_b
plaintext_b = bytes(c ^ k for c, k in zip(cipher_b, key))
print(f"Flag: {plaintext_b}")
```

### Resultado

```
54nt4_r54_wr4pp3d_th3_k35tr34m_but_x0r_53t_1t_fr33_h0h0h0@malwarespace.com
```

Para los últimos 2 bytes (`om`), calculamos:
```python
# XOR de los últimos bytes de cipher_a y cipher_b
last_xor = bytes(a ^ b for a, b in zip(cipher_a[-2:], cipher_b[-2:]))
# Resultado: b'om'
```

Completando la flag: termina en `.com`

---

## 🏆 Flag

Aplicando el formato MWS{...}:

```
MWS{54nt4_r54_wr4pp3d_th3_k35tr34m_but_x0r_53t_1t_fr33_h0h0h0@malwarespace.com}
```

### Decodificación del Leet Speak

| Leet | Texto |
|------|-------|
| 54nt4 | santa |
| r54 | rsa |
| wr4pp3d | wrapped |
| th3 | the |
| k35tr34m | keystream |
| x0r | xor |
| 53t | set |
| 1t | it |
| fr33 | free |
| h0h0h0 | hohoho |

**Mensaje completo:**
> "santa_rsa_wrapped_the_keystream_but_xor_set_it_free_hohoho@malwarespace.com"

🎅 Temática navideña: Santa cifró el keystream con RSA, pero XOR lo liberó!

---

## 📚 Lecciones Aprendidas

1. **Nunca reutilizar la misma clave XOR** para cifrar múltiples mensajes
2. **Datos embebidos** al final de binarios pueden contener información sensible
3. **Análisis estático** puede revelar strings y patrones sin necesidad de ejecución
4. **Known-plaintext attacks** son devastadores contra XOR simple

---

## 🔧 Herramientas Utilizadas

- Python 3 (json, base64)
- `file`, `strings`, `xxd`
- Análisis estático (sin ejecución del malware)

---

*Writeup by solving the CTF challenge on 2025-12-11*
