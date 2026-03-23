# Writeup: MediRev1 - Medical Cloud Exporter Reverse Engineering

## Información del Reto

- **Nombre**: MediRev1 (Medical Records Exporter)
- **Categoría**: Reverse Engineering + Cloud Security
- **Dificultad**: Media
- **Flag**: `CTF{m3d1cl0udx_r3v3rs3_3ng1n33r1ng_4ws_cr3d3nt14ls}`

## Descripción

El reto consistía en analizar código descompilado de un programa llamado "MediCloudX Data Exporter" que se conecta a AWS S3 para descargar registros médicos.

## Archivos Proporcionados

Se proporcionaron 10 archivos de código descompilado (`docu1.txt` a `docu10.txt`) generados por diferentes herramientas de decompilación (Ghidra, IDA, RetDec, etc.) del mismo binario.

## Solución Paso a Paso

### 1. Reconocimiento Inicial

Al revisar los archivos, identifiqué que se trataba de código C descompilado de un programa que:
- Se conecta a AWS S3
- Descarga registros médicos desde buckets específicos
- Utiliza autenticación AWS Signature V4

**Comandos iniciales**:
```bash
ls -la
file docu*.txt
```

### 2. Análisis del Código Descompilado

Revisé los archivos buscando información sensible. En `docu2.txt` y `docu3.txt` encontré la función `get_service_auth_token()`:

**docu2.txt (líneas 546-549)**:
```c
__builtin_strncpy(&part1.3, "YyKO6DUTjsrB", 0xd);
__builtin_strncpy(&complete_secret.4, "SECRET_REDACTED_BY_ANTIGRAVITY", 0x28);
__builtin_strncpy(&part2.2, "lLLctdbtcqRO", 0xd);
__builtin_strncpy(&part3.1, "Bs9fRnPImUEx0YyR", 0x11);
```

**docu4.txt (líneas 536-550)** - Versión Ghidra con valores hexadecimales:
```c
part1_3._0_8_ = 0x545544364f4b7959;  // "YyKO6DUT" (little-endian)
part1_3._8_4_ = 0x4272736a;          // "jsrB"
part2_2._0_8_ = 0x74626474634c4c6c;  // "lLLctdbt"
part2_2._8_4_ = 0x4f527163;          // "cqRO"
part3_1._0_8_ = 0x49506e5266397342;  // "Bs9fRnPI"
part3_1._8_8_ = 0x527959307845556d;  // "mUEx0YyR"
```

### 3. Extracción de Credenciales AWS

También encontré en `docu1.txt` (línea 355) el AWS Access Key ID:
```c
snprintf(&auth_header.0[0], 0x400,
    "AWS4-HMAC-SHA256 Credential=%s/%s/%s/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=%s",
    "AKIA_REDACTED_BY_ANTIGRAVITY", &v4, "us-east-1", &v14);
```

**Credenciales encontradas**:
- **Access Key ID**: `AKIA_REDACTED_BY_ANTIGRAVITY`
- **Secret Access Key**: `SECRET_REDACTED_BY_ANTIGRAVITY`
- **Región**: `us-east-1`

### 4. Identificación del Bucket S3

En el código encontré que el formato del bucket es:
```c
snprintf(&s, 0x100, "ctf-25-medical-exporter-records-%s", bucket_suffix);
```

Pero el sufijo no estaba hardcodeado. Necesitaba descubrirlo.

### 5. Validación de Credenciales AWS

Creé un script Python para validar las credenciales:

```python
import boto3

AWS_ACCESS_KEY = "AKIA_REDACTED_BY_ANTIGRAVITY"
AWS_SECRET_KEY = "SECRET_REDACTED_BY_ANTIGRAVITY"

session = boto3.Session(
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY,
    region_name="us-east-1"
)

sts = session.client('sts')
identity = sts.get_caller_identity()
print(identity)
```

**Resultado**:
```json
{
    "UserId": "AIDA5HCACCPUMUBUWBXEA",
    "Account": "908519937000",
    "Arn": "arn:aws:iam::908519937000:user/ctf-25-medical-exporter-service-u145wnn0"
}
```

🔑 **Clave del reto**: El nombre del usuario IAM termina con `u145wnn0` - ¡este es el sufijo del bucket!

### 6. Acceso al Bucket S3

Con el sufijo identificado, construí el nombre completo del bucket:
```
ctf-25-medical-exporter-records-u145wnn0
```

Listé los objetos del bucket:

```python
s3_client = boto3.client('s3',
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY,
    region_name='us-east-1'
)

response = s3_client.list_objects_v2(
    Bucket='ctf-25-medical-exporter-records-u145wnn0'
)
```

**Objetos encontrados**:
```
- admin/system_backup/flag.txt (51 bytes) ⭐
- exports/cardiovascular_patients.json (216 bytes)
- exports/lab_results.json (273 bytes)
- exports/patient_manifest.json (368 bytes)
```

### 7. Extracción de la Flag

Descargué el archivo `admin/system_backup/flag.txt`:

```python
response = s3_client.get_object(
    Bucket='ctf-25-medical-exporter-records-u145wnn0',
    Key='admin/system_backup/flag.txt'
)
flag = response['Body'].read().decode('utf-8')
print(flag)
```

**Flag obtenida**:
```
CTF{m3d1cl0udx_r3v3rs3_3ng1n33r1ng_4ws_cr3d3nt14ls}
```

## Scripts Utilizados

### Script 1: Validación de Credenciales (`test_aws_creds.py`)

```python
#!/usr/bin/env python3
import boto3
from botocore.config import Config

AWS_ACCESS_KEY = "AKIA_REDACTED_BY_ANTIGRAVITY"
AWS_SECRET_KEY = "SECRET_REDACTED_BY_ANTIGRAVITY"
REGION = "us-east-1"

config = Config(region_name=REGION)
session = boto3.Session(
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY,
    region_name=REGION
)

# Obtener identidad
sts = session.client('sts', config=config)
identity = sts.get_caller_identity()
print(f"Usuario ARN: {identity['Arn']}")
print(f"Account ID: {identity['Account']}")
```

### Script 2: Extracción de Flag (`get_flag_final.py`)

```python
#!/usr/bin/env python3
import boto3

AWS_ACCESS_KEY = "AKIA_REDACTED_BY_ANTIGRAVITY"
AWS_SECRET_KEY = "SECRET_REDACTED_BY_ANTIGRAVITY"
BUCKET_SUFFIX = "u145wnn0"
BUCKET_NAME = f"ctf-25-medical-exporter-records-{BUCKET_SUFFIX}"

s3_client = boto3.client('s3',
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY,
    region_name='us-east-1'
)

# Listar objetos
response = s3_client.list_objects_v2(Bucket=BUCKET_NAME)
for obj in response['Contents']:
    print(f"{obj['Key']} ({obj['Size']} bytes)")

# Descargar flag
response = s3_client.get_object(
    Bucket=BUCKET_NAME,
    Key='admin/system_backup/flag.txt'
)
print(response['Body'].read().decode('utf-8'))
```

## Conceptos Técnicos Aplicados

### 1. Reverse Engineering
- Análisis de código descompilado de múltiples herramientas
- Identificación de strings y credenciales hardcodeadas
- Reconstrucción de la lógica del programa

### 2. AWS Security
- AWS IAM (Identity and Access Management)
- AWS STS (Security Token Service) - GetCallerIdentity
- AWS S3 bucket naming conventions
- Firma de peticiones AWS Signature V4

### 3. Enumeración de Cloud
- Validación de credenciales AWS
- Listado de objetos en buckets S3
- Descarga de archivos desde S3

### 4. Python para Security
- Uso de `boto3` para interactuar con AWS
- Manejo de credenciales programáticamente
- Automatización de enumeración

## Vulnerabilidades Identificadas

1. **Credenciales Hardcodeadas**: Las credenciales AWS estaban embebidas directamente en el binario
2. **Información Sensible Expuesta**: El Access Key ID y Secret Access Key son recuperables mediante reversing
3. **Permisos IAM Excesivos**: El usuario tiene permisos para listar y leer objetos del bucket
4. **Naming Convention Predecible**: El sufijo del bucket está relacionado con el nombre del usuario IAM

## Mejores Prácticas de Seguridad (Recomendaciones)

### Para Desarrolladores

1. **NUNCA hardcodear credenciales**:
   - Usar variables de entorno
   - AWS Systems Manager Parameter Store
   - AWS Secrets Manager
   - IAM Roles para EC2/Lambda

2. **Usar IAM Roles en lugar de Access Keys**:
   ```python
   # Mal ❌
   client = boto3.client('s3',
       aws_access_key_id='AKIA...',
       aws_secret_access_key='secret...'
   )

   # Bien ✅
   client = boto3.client('s3')  # Usa IAM Role automáticamente
   ```

3. **Principio de Mínimo Privilegio**:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Action": [
         "s3:GetObject"
       ],
       "Resource": "arn:aws:s3:::specific-bucket/specific-prefix/*"
     }]
   }
   ```

4. **Rotación de Credenciales**: Implementar rotación automática de Access Keys

5. **Ofuscación NO es Seguridad**: Aunque el código esté compilado, puede ser decompilado

## Herramientas Utilizadas

- **Análisis de código**: Editor de texto, grep
- **Reversing**: Ghidra, IDA Pro, RetDec (archivos ya proporcionados)
- **AWS CLI/SDK**: boto3 (Python)
- **Python 3**: Scripts de automatización
- **Virtual Environment**: Para aislar dependencias

## Comandos Ejecutados

```bash
# Configurar entorno
python3 -m venv venv
source venv/bin/activate
pip install boto3

# Validar credenciales
python3 test_aws_creds.py

# Extraer flag
python3 get_flag_final.py
```

## Timeline de Resolución

1. ✅ Análisis inicial de archivos (5 min)
2. ✅ Búsqueda de credenciales en código (10 min)
3. ✅ Identificación de Access Key y Secret Key (5 min)
4. ✅ Primer intento de acceso a S3 - sin sufijo (5 min)
5. ✅ Validación de credenciales con STS (5 min)
6. ✅ Identificación del sufijo del bucket desde IAM ARN (2 min)
7. ✅ Acceso exitoso al bucket (1 min)
8. ✅ Extracción de la flag (1 min)

**Tiempo total**: ~35 minutos

## Lessons Learned

1. **Múltiples herramientas de decompilación son útiles**: Diferentes decompiladores muestran el código de formas distintas, algunas más claras que otras.

2. **Las credenciales en binarios son recuperables**: Cualquier secret hardcodeado en un binario puede ser extraído.

3. **La información del usuario IAM puede revelar pistas**: El nombre del usuario IAM contenía el sufijo necesario para el bucket.

4. **AWS STS GetCallerIdentity es útil para reconocimiento**: Permite validar credenciales y obtener información sobre el usuario.

## Referencias

- [AWS Security Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [Boto3 Documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)
- [AWS Signature Version 4](https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html)
- [OWASP - Hardcoded Credentials](https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password)

## Estructura de Archivos del Reto

```
medirev1/
├── docu1.txt                  # Código descompilado (IDA/Ghidra)
├── docu2.txt                  # Código descompilado (Binary Ninja)
├── docu3.txt                  # Código descompilado (RetDec)
├── docu4.txt                  # Código descompilado (Ghidra - hexadecimal)
├── docu5.txt - docu10.txt     # Otras versiones
├── venv/                      # Python virtual environment
├── analyze_secret.py          # Script de análisis del secret
├── find_bucket.py             # Script para encontrar bucket
├── test_aws_creds.py          # Script de validación de credenciales
├── get_flag_final.py          # Script final de extracción
└── WRITEUP.md                 # Este documento
```

## Flag Final

```
CTF{m3d1cl0udx_r3v3rs3_3ng1n33r1ng_4ws_cr3d3nt14ls}
```

---

**Autor**: CTF Team
**Fecha**: Noviembre 2025
**Challenge**: MediRev1 - AlpacaCTF
