# Writeup: Demasiado Ruido

**Categoría:** Web / Side Channel
**Reto:** Demasiado Ruido
**Objetivo:** Encontrar la flag oculta en el sitio web.

## 1. Reconocimiento Inicial

Al acceder a la página principal, nos encontramos con un sitio educativo sobre telecomunicaciones (Fibra óptica, RF, Ruido, etc.).

Al revisar las diferentes secciones, dos pistas fueron fundamentales:
1.  **El nombre del reto ("Demasiado ruido") y la sección `metadata.html`:**
    El texto en la sección de metadatos decía: *"No toda la información está en el payload... En comunicaciones, el canal también puede 'hablar'."* Esto sugiere que la información no está en el contenido (HTML/Body), sino en el protocolo o metadatos de transporte.
2.  **Patrón en los archivos:**
    Al inspeccionar el código fuente y las peticiones de red, noté que todos los recursos estáticos tenían nombres numéricos secuenciales:
    *   `/css/0.css`
    *   `/js/1.js`
    *   `/img/2.png`
    *   ... hasta `/img/55.png`.

## 2. Análisis del Canal Lateral (HTTP Status Codes)

Al inspeccionar las cabeceras HTTP de estos archivos secuenciales para ver si el "canal" nos estaba diciendo algo, notamos un comportamiento inusual.

Al hacer una petición a `http://20.81.206.3:61251/css/0.css`:
```bash
curl -I http://20.81.206.3:61251/css/0.css
```
El servidor respondió con un **Status Code: 224** en lugar del esperado `200 OK`.

Probando con el siguiente archivo, `/js/1.js`, devolvió un **Status Code: 254**.

Esto confirmó la vulnerabilidad de tipo *Side Channel*: la flag está codificada en los códigos de estado HTTP de los recursos cargados por la página, ordenados por su numeración.

## 3. Extracción y Decodificación

Escribí un script para automatizar la extracción:
1.  Recorrer los archivos en orden numérico (0 a 55).
2.  Guardar el código de estado de cada uno.

Los códigos obtenidos fueron:
`[224, 254, 261, 245, 228, ...]`

Al restar 200 a cada valor, obtenemos números en el rango de 0 a 64, lo que coincide con los índices del alfabeto **Base64**.

*   `224 - 200 = 24` -> Carácter 'Y'
*   `254 - 200 = 54` -> Carácter '2'
*   ...
*   `264 - 200 = 64` -> Carácter de padding '='.

### Script de Solución (Python)

```python
import requests
import base64
import re

base_url = "http://20.81.206.3:61251"

# Extraemos todos los paths numerados del sitio
# ... (lógica de scraping omitida para brevedad) ...

files = ["/css/0.css", "/js/1.js", "/img/2.png", "..."] # 56 archivos en total

# Ordenar numéricamente por el ID del archivo
files.sort(key=lambda x: int(re.search(r'/(\d+)\.', x).group(1)))

codes = []
for f in files:
    r = requests.get(base_url + f)
    codes.append(r.status_code)

# Mapeo a Base64
b64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
encoded_str = ""
for c in codes:
    val = c - 200
    if 0 <= val <= 63:
        encoded_str += b64_alphabet[val]
    elif val == 64:
        encoded_str += "="

# Decodificación final
flag = base64.b64decode(encoded_str).decode('utf-8')
print(f"FLAG: {flag}")
```

## 4. Resultado

La cadena Base64 reconstruida fue:
`Y29tc29jdXBje3kwdV80cjNfejBfbjAxenlfOERTN0dKc2Q5MEQzfQ==`

Al decodificarla obtenemos la flag final:

**`comsocupc{y0u_4r3_z0_n01zy_8DS7GJsd90D3}`**
