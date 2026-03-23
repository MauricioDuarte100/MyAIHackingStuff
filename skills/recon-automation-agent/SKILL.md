# Recon Automation Agent

Especialista en recon-automation-agent

## Instructions
Eres un experto de élite en recon-automation-agent. Tu objetivo es ejecutar la siguiente metodología con precisión quirúrgica y eficiencia técnica.

# 🔍 Recon Automation Agent
## Automatización Completa de Reconocimiento

---

## OVERVIEW

Este agente proporciona scripts y pipelines de automatización completos para reconocimiento en bug bounty, integrando las mejores herramientas disponibles en 2025.

---

## PIPELINE COMPLETO DE RECONOCIMIENTO

```bash
#!/bin/bash
# full_recon.sh - Pipeline completo de reconocimiento

TARGET=$1
OUTPUT_DIR="recon_$TARGET"

mkdir -p $OUTPUT_DIR/{subdomains,urls,ports,screenshots,js,params,nuclei}

echo "[*] Starting full recon on $TARGET"

# ============================================
# FASE 1: SUBDOMAIN ENUMERATION
# ============================================

echo "[1/8] Subdomain Enumeration..."

# Passive - Multiple sources
subfinder -d $TARGET -all -silent -o $OUTPUT_DIR/subdomains/subfinder.txt
amass enum -passive -d $TARGET -o $OUTPUT_DIR/subdomains/amass.txt
assetfinder --subs-only $TARGET > $OUTPUT_DIR/subdomains/assetfinder.txt
findomain -t $TARGET -q > $OUTPUT_DIR/subdomains/findomain.txt

# Certificate Transparency
curl -s "https://crt.sh/?q=%.$TARGET&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > $OUTPUT_DIR/subdomains/crtsh.txt

# GitHub dorking
github-subdomains -d $TARGET -t $GITHUB_TOKEN -o $OUTPUT_DIR/subdomains/github.txt 2>/dev/null

# Combine and dedupe
cat $OUTPUT_DIR/subdomains/*.txt | sort -u > $OUTPUT_DIR/subdomains/all_passive.txt
echo "[+] Found $(wc -l < $OUTPUT_DIR/subdomains/all_passive.txt) passive subdomains"

# Active brute force
echo "[1b/8] Active subdomain bruteforce..."
puredns bruteforce /usr/share/wordlists/dns/subdomains-top1million-110000.txt $TARGET -r resolvers.txt -w $OUTPUT_DIR/subdomains/bruteforce.txt

# Final combination
cat $OUTPUT_DIR/subdomains/all_passive.txt $OUTPUT_DIR/subdomains/bruteforce.txt | sort -u > $OUTPUT_DIR/subdomains/all_subdomains.txt
echo "[+] Total unique subdomains: $(wc -l < $OUTPUT_DIR/subdomains/all_subdomains.txt)"

# ============================================
# FASE 2: DNS RESOLUTION & FILTERING
# ============================================

echo "[2/8] DNS Resolution..."

# Resolve all subdomains
dnsx -l $OUTPUT_DIR/subdomains/all_subdomains.txt -silent -a -resp -o $OUTPUT_DIR/subdomains/resolved.txt

# Extract IPs
cat $OUTPUT_DIR/subdomains/resolved.txt | cut -d '[' -f2 | cut -d ']' -f1 | sort -u > $OUTPUT_DIR/subdomains/ips.txt

# ============================================
# FASE 3: HTTP PROBING
# ============================================

echo "[3/8] HTTP Probing..."

# Probe for live hosts
httpx -l $OUTPUT_DIR/subdomains/all_subdomains.txt -silent -title -status-code -tech-detect -content-length -follow-redirects -o $OUTPUT_DIR/subdomains/httpx_output.txt

# Extract live URLs
cat $OUTPUT_DIR/subdomains/httpx_output.txt | cut -d ' ' -f1 > $OUTPUT_DIR/subdomains/live_urls.txt
echo "[+] Live hosts: $(wc -l < $OUTPUT_DIR/subdomains/live_urls.txt)"

# ============================================
# FASE 4: PORT SCANNING
# ============================================

echo "[4/8] Port Scanning..."

# Fast port scan on IPs
naabu -list $OUTPUT_DIR/subdomains/ips.txt -top-ports 1000 -silent -o $OUTPUT_DIR/ports/naabu_output.txt

# Service detection on open ports
cat $OUTPUT_DIR/ports/naabu_output.txt | httpx -silent -title -o $OUTPUT_DIR/ports/http_services.txt

# ============================================
# FASE 5: URL DISCOVERY
# ============================================

echo "[5/8] URL Discovery..."

# Wayback Machine
cat $OUTPUT_DIR/subdomains/live_urls.txt | waybackurls > $OUTPUT_DIR/urls/wayback.txt

# GAU (GetAllUrls)
cat $OUTPUT_DIR/subdomains/live_urls.txt | gau --threads 5 > $OUTPUT_DIR/urls/gau.txt

# Crawling
katana -list $OUTPUT_DIR/subdomains/live_urls.txt -d 3 -jc -silent -o $OUTPUT_DIR/urls/katana.txt

# gospider
gospider -S $OUTPUT_DIR/subdomains/live_urls.txt -d 2 -c 10 -t 5 --other-source -o $OUTPUT_DIR/urls/gospider/

# Combine
cat $OUTPUT_DIR/urls/*.txt $OUTPUT_DIR/urls/gospider/* 2>/dev/null | sort -u > $OUTPUT_DIR/urls/all_urls.txt
echo "[+] Total URLs: $(wc -l < $OUTPUT_DIR/urls/all_urls.txt)"

# ============================================
# FASE 6: PARAMETER DISCOVERY
# ============================================

echo "[6/8] Parameter Discovery..."

# Extract URLs with parameters
cat $OUTPUT_DIR/urls/all_urls.txt | grep "=" | sort -u > $OUTPUT_DIR/params/urls_with_params.txt

# Parameter mining with Arjun
arjun -i $OUTPUT_DIR/subdomains/live_urls.txt -oT $OUTPUT_DIR/params/arjun_params.txt -t 10

# GF patterns
cat $OUTPUT_DIR/urls/all_urls.txt | gf xss > $OUTPUT_DIR/params/gf_xss.txt
cat $OUTPUT_DIR/urls/all_urls.txt | gf sqli > $OUTPUT_DIR/params/gf_sqli.txt
cat $OUTPUT_DIR/urls/all_urls.txt | gf ssrf > $OUTPUT_DIR/params/gf_ssrf.txt
cat $OUTPUT_DIR/urls/all_urls.txt | gf redirect > $OUTPUT_DIR/params/gf_redirect.txt
cat $OUTPUT_DIR/urls/all_urls.txt | gf lfi > $OUTPUT_DIR/params/gf_lfi.txt
cat $OUTPUT_DIR/urls/all_urls.txt | gf rce > $OUTPUT_DIR/params/gf_rce.txt

# ============================================
# FASE 7: JAVASCRIPT ANALYSIS
# ============================================

echo "[7/8] JavaScript Analysis..."

# Extract JS files
cat $OUTPUT_DIR/urls/all_urls.txt | grep -iE "\.js$|\.js\?" | sort -u > $OUTPUT_DIR/js/js_files.txt

# Download JS files
cat $OUTPUT_DIR/js/js_files.txt | xargs -P 10 -I {} wget -q -P $OUTPUT_DIR/js/files/ {}

# Find endpoints in JS
cat $OUTPUT_DIR/js/js_files.txt | while read url; do
    python3 linkfinder.py -i "$url" -o cli
done > $OUTPUT_DIR/js/endpoints.txt 2>/dev/null

# Find secrets in JS
cat $OUTPUT_DIR/js/js_files.txt | nuclei -t exposures/tokens/ -silent -o $OUTPUT_DIR/js/secrets.txt

# ============================================
# FASE 8: VULNERABILITY SCANNING
# ============================================

echo "[8/8] Vulnerability Scanning..."

# Nuclei scan
nuclei -l $OUTPUT_DIR/subdomains/live_urls.txt -t cves/ -t vulnerabilities/ -t exposures/ -t misconfiguration/ -t takeovers/ -silent -o $OUTPUT_DIR/nuclei/scan_results.txt

# Subdomain takeover check
subzy run --targets $OUTPUT_DIR/subdomains/all_subdomains.txt --concurrency 50 --hide_fails -o $OUTPUT_DIR/nuclei/takeover.txt

echo "[*] Recon completed! Results in $OUTPUT_DIR"
```

---

## HERRAMIENTAS ESENCIALES 2025

### Subdomain Enumeration

```yaml
passive_tools:
  - name: subfinder
    install: "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    usage: "subfinder -d target.com -all -silent"
    sources: "50+ passive sources"
    
  - name: amass
    install: "go install -v github.com/owasp-amass/amass/v4/...@master"
    usage: "amass enum -passive -d target.com"
    sources: "Comprehensive OSINT"
    
  - name: assetfinder
    install: "go install github.com/tomnomnom/assetfinder@latest"
    usage: "assetfinder --subs-only target.com"
    
  - name: findomain
    install: "cargo install findomain"
    usage: "findomain -t target.com -q"
    
  - name: github-subdomains
    install: "go install github.com/gwen001/github-subdomains@latest"
    usage: "github-subdomains -d target.com -t TOKEN"

active_tools:
  - name: puredns
    install: "go install github.com/d3mondev/puredns/v2@latest"
    usage: "puredns bruteforce wordlist.txt target.com -r resolvers.txt"
    
  - name: shuffledns
    install: "go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
    usage: "shuffledns -d target.com -w wordlist.txt -r resolvers.txt"
```

### HTTP Probing

```yaml
tools:
  - name: httpx
    install: "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
    usage: "httpx -l hosts.txt -silent -title -status-code -tech-detect"
    features:
      - Title extraction
      - Status codes
      - Tech detection (Wappalyzer)
      - Content length
      - Web server
      - TLS info
      
  - name: httprobe
    install: "go install github.com/tomnomnom/httprobe@latest"
    usage: "cat hosts.txt | httprobe"
```

### URL Discovery

```yaml
tools:
  - name: waybackurls
    install: "go install github.com/tomnomnom/waybackurls@latest"
    usage: "waybackurls target.com"
    source: "Wayback Machine"
    
  - name: gau
    install: "go install github.com/lc/gau/v2/cmd/gau@latest"
    usage: "gau target.com"
    sources: "Wayback, Common Crawl, AlienVault OTX"
    
  - name: katana
    install: "go install github.com/projectdiscovery/katana/cmd/katana@latest"
    usage: "katana -u https://target.com -d 3 -jc"
    features: "JavaScript crawling, form parsing"
    
  - name: gospider
    install: "go install github.com/jaeles-project/gospider@latest"
    usage: "gospider -s https://target.com -d 2 -c 10"
    
  - name: hakrawler
    install: "go install github.com/hakluke/hakrawler@latest"
    usage: "echo https://target.com | hakrawler -d 2"
```

### Port Scanning

```yaml
tools:
  - name: naabu
    install: "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    usage: "naabu -host target.com -top-ports 1000"
    features: "SYN scan, service detection"
    
  - name: masscan
    install: "apt install masscan"
    usage: "masscan -p1-65535 target.com --rate 10000"
    
  - name: rustscan
    install: "cargo install rustscan"
    usage: "rustscan -a target.com -- -sV"
```

### Parameter Discovery

```yaml
tools:
  - name: arjun
    install: "pip install arjun"
    usage: "arjun -u https://target.com/page -oT params.txt"
    
  - name: paramspider
    install: "pip install paramspider"
    usage: "paramspider -d target.com"
    
  - name: gf
    install: "go install github.com/tomnomnom/gf@latest"
    usage: "cat urls.txt | gf xss"
    patterns:
      - xss
      - sqli
      - ssrf
      - redirect
      - lfi
      - rce
      - idor
      - debug_logic
```

### Content Discovery

```yaml
tools:
  - name: feroxbuster
    install: "cargo install feroxbuster"
    usage: "feroxbuster -u https://target.com -w wordlist.txt -t 50"
    features: "Recursive, fast, multiple extensions"
    
  - name: ffuf
    install: "go install github.com/ffuf/ffuf/v2@latest"
    usage: "ffuf -u https://target.com/FUZZ -w wordlist.txt"
    
  - name: dirsearch
    install: "pip install dirsearch"
    usage: "dirsearch -u https://target.com -e php,html,js"
    
  - name: gobuster
    install: "go install github.com/OJ/gobuster/v3@latest"
    usage: "gobuster dir -u https://target.com -w wordlist.txt"
```

### Vulnerability Scanning

```yaml
tools:
  - name: nuclei
    install: "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    usage: "nuclei -l urls.txt -t cves/ -t vulnerabilities/"
    templates: "8000+ community templates"
    categories:
      - cves
      - vulnerabilities
      - exposures
      - misconfiguration
      - takeovers
      - file
      - fuzzing
      
  - name: nikto
    install: "apt install nikto"
    usage: "nikto -h https://target.com"
    
  - name: wpscan
    install: "gem install wpscan"
    usage: "wpscan --url https://target.com --api-token TOKEN"
```

---

## WORDLISTS RECOMENDADAS

```yaml
subdomain_wordlists:
  - "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt"
  - "/usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt"
  - "/usr/share/amass/wordlists/subdomains-top1mil-5000.txt"
  
directory_wordlists:
  - "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"
  - "/usr/share/seclists/Discovery/Web-Content/common.txt"
  - "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt"
  
parameter_wordlists:
  - "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"
  - "/usr/share/seclists/Discovery/Web-Content/api-endpoints.txt"
  
api_wordlists:
  - "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt"
  - "/usr/share/seclists/Discovery/Web-Content/swagger.txt"
```

---

## GOOGLE DORKS AUTOMATION

```python
#!/usr/bin/env python3
"""google_dorks.py - Automated Google dorking"""

DORKS = {
    'sensitive_files': [
        'site:{target} ext:sql | ext:db | ext:log | ext:cfg | ext:bak',
        'site:{target} ext:xml | ext:conf | ext:cnf | ext:ini',
        'site:{target} ext:env | ext:yaml | ext:yml | ext:toml',
    ],
    'admin_panels': [
        'site:{target} inurl:admin | inurl:administrator | inurl:dashboard',
        'site:{target} inurl:login | inurl:signin | inurl:auth',
        'site:{target} intitle:"admin" | intitle:"dashboard" | intitle:"panel"',
    ],
    'sensitive_info': [
        'site:{target} "password" | "passwd" | "pwd" ext:txt | ext:log',
        'site:{target} "api_key" | "apikey" | "api-key"',
        'site:{target} "secret" | "token" | "bearer"',
    ],
    'exposed_documents': [
        'site:{target} ext:pdf | ext:doc | ext:docx | ext:xls | ext:xlsx',
        'site:{target} ext:ppt | ext:pptx | ext:csv',
    ],
    'subdomains': [
        'site:*.{target}',
        'site:*.*.{target}',
    ],
    'errors': [
        'site:{target} "error" | "warning" | "exception"',
        'site:{target} "stack trace" | "syntax error"',
    ],
    'directories': [
        'site:{target} intitle:"index of"',
        'site:{target} intitle:"directory listing"',
    ],
}

def generate_dorks(target):
    """Generate dorks for target"""
    results = []
    for category, dorks in DORKS.items():
        for dork in dorks:
            results.append({
                'category': category,
                'dork': dork.format(target=target)
            })
    return results
```

---

## GITHUB RECON

```python
#!/usr/bin/env python3
"""github_recon.py - Search for secrets in GitHub"""

import requests
import os

GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')

GITHUB_DORKS = [
    '"{target}" password',
    '"{target}" api_key',
    '"{target}" apikey',
    '"{target}" secret',
    '"{target}" token',
    '"{target}" aws_access_key',
    '"{target}" aws_secret',
    '"{target}" BEGIN RSA PRIVATE KEY',
    '"{target}" jdbc:mysql',
    '"{target}" mongodb+srv',
    'org:{target} password',
    'org:{target} secret',
]

def search_github(target):
    """Search GitHub for sensitive info"""
    headers = {'Authorization': f'token {GITHUB_TOKEN}'}
    results = []
    
    for dork in GITHUB_DORKS:
        query = dork.format(target=target)
        url = f'https://api.github.com/search/code?q={query}'
        
        r = requests.get(url, headers=headers)
        if r.status_code == 200:
            data = r.json()
            for item in data.get('items', []):
                results.append({
                    'query': query,
                    'repo': item['repository']['full_name'],
                    'path': item['path'],
                    'url': item['html_url']
                })
    
    return results
```

---

## SHODAN/CENSYS RECON

```python
#!/usr/bin/env python3
"""shodan_recon.py - Internet-wide scanning data"""

import shodan

SHODAN_API_KEY = os.getenv('SHODAN_API_KEY')

def shodan_recon(target):
    """Query Shodan for target info"""
    api = shodan.Shodan(SHODAN_API_KEY)
    
    results = {
        'hosts': [],
        'ports': set(),
        'services': [],
        'vulns': []
    }
    
    # Search by domain
    query = f'hostname:{target}'
    
    for result in api.search_cursor(query):
        results['hosts'].append(result['ip_str'])
        results['ports'].add(result['port'])
        
        if 'vulns' in result:
            results['vulns'].extend(result['vulns'])
            
        results['services'].append({
            'ip': result['ip_str'],
            'port': result['port'],
            'product': result.get('product', 'unknown'),
            'version': result.get('version', 'unknown')
        })
    
    return results
```

---

## OUTPUT STRUCTURE

```
01-recon/
├── subdomains/
│   ├── passive/
│   │   ├── subfinder.txt
│   │   ├── amass.txt
│   │   ├── crtsh.txt
│   │   └── github.txt
│   ├── active/
│   │   └── bruteforce.txt
│   ├── all_subdomains.txt
│   └── live_hosts.txt
├── urls/
│   ├── wayback.txt
│   ├── gau.txt
│   ├── katana.txt
│   └── all_urls.txt
├── ports/
│   ├── naabu.txt
│   └── services.txt
├── js/
│   ├── files/
│   ├── endpoints.txt
│   └── secrets.txt
├── params/
│   ├── arjun.txt
│   └── gf_patterns/
├── screenshots/
│   └── gowitness/
├── nuclei/
│   └── scan_results.txt
└── reports/
    └── recon_summary.md
```

---

**Versión**: 1.0
**Última actualización**: 2025
**Modelo recomendado**: sonnet


## Available Resources
- . (Directorio de la skill)
