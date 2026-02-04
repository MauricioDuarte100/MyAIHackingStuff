---
trigger: always_on
---

quiero que hackees eticamente teniendo en cuenta esto 
### Footprinting & Fingerprinting

#### Fingerprinting del Servidor Web y Tecnologías

- **Identificación del Servidor Web:**
    - [ ] ¿Qué tipo de Web Server es? (Apache, Nginx, IIS, etc.)
    - [ ] ¿Versión del servidor web?
- **Identificación Activa de Infraestructura:**
    - [ ] **Cabeceras HTTP:**
        - [ ] `curl -I http://<IP>` o `curl -s -v http://<IP>`
        - [ ] `Server`: Identificar software y versión del servidor.
        - [ ] `X-Powered-By`: Identificar tecnologías (PHP, ASP.NET, JSP, etc.).
        - [ ] `X-AspNet-Version`, `X-AspNetMvc-Version`.
    - [ ] **Cookies:**
        - [ ] Identificar cookies de sesión y tecnología subyacente:
            - [ ] .NET: `ASPSESSIONID<RANDOM>=<COOKIE_VALUE>`
            - [ ] PHP: `PHPSESSID=<COOKIE_VALUE>`
            - [ ] JAVA: `JSESSIONID=<COOKIE_VALUE>` (o `JSESSION` según tu lista)
    - [ ] **Análisis de Errores:**
        - [ ] Provocar errores para revelar software/versión (URLs inválidas, parámetros incorrectos).
    - [ ] **Herramientas de Fingerprinting:**
        - [ ] **Wappalyzer:** Identificar tecnologías (CMS, frameworks, librerías JS, etc.).
        - [ ] **WhatWeb:** `whatweb http://<IP>` para una identificación detallada.
        - [ ] **BuiltWith:** Usar la web o extensión para análisis tecnológico.
        - [ ] **Netcraft:** Consultar el informe del sitio para tecnología, proveedor de hosting y postura de seguridad.
        - [ ] **Nikto:** `nikto -h <dominio_o_IP> -Tuning x 1 2 3 b` (la `b` es para `Security Headers` y `Allowed Methods` según tu entrada). Revisar vulnerabilidades conocidas y archivos interesantes.
        - [ ] **Nuclei:**
            - [ ] `nuclei -u http://<IP> -t "technologies/"` (para detección de tecnología).
            - [ ] `nuclei -u http://<IP> -t "misconfiguration/"` (para cabeceras y misconfigs).
    - [ ] **Detección de WAF:**
        - [ ] `wafw00f -v https://<dominio>`
    - [ ] **Aquatone:**
        - [ ] `cat subdominios.txt | aquatone -ports large` (para escaneo de puertos y screenshots de subdominios).
- **Identificación de CMS y Frameworks:**
    - [ ] ¿Utiliza un CMS? (WordPress, Joomla, Drupal, etc.)
        - [ ] Identificar rutas específicas del CMS (ej. `/wp-admin`, `/administrator`).
    - [ ] ¿Tecnología de Backend? (PHP, Java, ASPX, Node.js, Python, Ruby)
    - [ ] ¿Framework específico? (Laravel, Express, Django, Rails, Spring, etc.)
- **Identificación de APIs:**
    - [ ] ¿Hay APIs expuestas? (REST, SOAP, GraphQL)
    - [ ] ¿Parámetros de consulta en URLs que sugieran APIs? (`/api/`, `?id=`)
    - [ ] (Para más detalles, ver sección específica de APIs).
- **Proxy AJP:**
    - [ ] Realizar escaneo `nmap -sV -p 8009 <IP>` para el puerto `8009/tcp`. Si está abierto, revisar sección _AJP Proxy_ en **Ataques del Lado del Servidor**.
- **Pila Tecnológica de Backend:**
    - [ ] ¿LAMP, WAMP, MAMP, XAMPP, MEAN, etc.?
- **Base de Datos:**
    - [ ] ¿Se puede inferir la base de datos utilizada? (MySQL, PostgreSQL, MongoDB, SQL Server, Oracle)
    - [ ] ¿Relacional o NoSQL?
- **Certificado TLS/SSL:**
    - [ ] Revisar certificado (emisor, validez, algoritmos).
    - [ ] Revisar versión de TLS y configuraciones (ciphersuites débiles). Herramientas como `testssl.sh` o Qualys SSL Labs.

#### Búsqueda y Análisis de Metarchivos y Contenido Estándar

- [ ] **`robots.txt`:**
    - [ ] Revisar `http://<dominio>/robots.txt`.
    - [ ] Identificar directorios `Disallow`: ¿Rutas sensibles, paneles de administración, backups?
    - [ ] Mapear estructura del sitio basada en `Disallow` y `Allow`.
    - [ ] Detectar posibles trampas para crawlers (honeypots).
    - [ ] ¿Revela el tipo de CMS? (ej. `/wp-admin/` en `Disallow` para WordPress).
- [ ] **URIs `.well-known` (RFC 8615):**
    - [ ] Revisar `http://<dominio>/.well-known/`.
    - [ ] `security.txt` (RFC 9116): `/.well-known/security.txt` o `/security.txt`. ¿Contiene información de contacto para reporte de vulnerabilidades?
    - [ ] `change-password`: `/.well-known/change-password`.
    - [ ] `openid-configuration`: `/.well-known/openid-configuration`.
    - [ ] `assetlinks.json` (Digital Asset Links).
    - [ ] `mta-sts.txt` (MTA Strict Transport Security, RFC 8461).
- [ ] **`sitemap.xml`:**
    - [ ] Revisar `http://<dominio>/sitemap.xml` (o variaciones).
    - [ ] Identificar todas las URLs listadas para entender la estructura y contenido completo del sitio.
- [ ] **`humans.txt`:**
    - [ ] Revisar `http://<dominio>/humans.txt`. ¿Información sobre el equipo de desarrollo o tecnologías?
- [ ] **`Security.txt`:** (Ya cubierto en `.well-known`, pero verificar ambas ubicaciones).

#### Revisión Inicial del Contenido Web

- **Análisis del Código Fuente (HTML, CSS, JS):**
    - [ ] **Tags HTML Clave:**
        - [ ] `<head>`: Metadatos, enlaces a scripts/CSS.
        - [ ] `<body>`: Contenido visible.
        - [ ] `<style>`: CSS incrustado.
        - [ ] `<script>`: JavaScript incrustado o enlaces a archivos `.js`.
    - [ ] **Exposición de Datos Sensibles en el Código Fuente:**
        - [ ] Comentarios HTML/JS: ¿Credenciales, hashes, claves API, rutas internas, información de depuración?
        - [ ] Enlaces expuestos (URLs ocultas o de prueba).
        - [ ] Directorios o archivos referenciados.
        - [ ] Información de usuarios.
    - [ ] **Análisis de Archivos JavaScript (`.js`):**
        - [ ] ¿Archivos minificados (`.min.js`)? Usar "Beautifiers" (ej. `jsbeautifier.org`) para mejorar legibilidad.
        - [ ] ¿Ofuscación `p,a,c,k,e,d`? Usar "UnPacker" (ej. `matthewfl.com/unPacker.html`).
        - [ ] ¿Otros tipos de ofuscación?
        - [ ] Analizar código desofuscado:
            - [ ] Endpoints de API, lógica de negocio, parámetros ocultos.
            - [ ] Identificar hashes comunes (Base64, Hex, Caesar/ROT13).
                - [ ] Hex: strings con caracteres 0-9 y a-f.
            - [ ] Usar identificadores de cifrado si es necesario (ej. Cipher Identifier de Boxentriq).
            - [ ] Buscar funciones de generación de tokens o lógica de validación del lado del cliente.
- **Crawling y Spidering:**
    - [ ] Utilizar herramientas para descubrir contenido y funcionalidad:
        - [ ] **Burp Suite Spider:** Mapear la aplicación, identificar contenido oculto.
        - [ ] **OWASP ZAP Spider/AJAX Spider.**
        - [ ] **FinalRecon:** `python finalrecon.py --full <dominio>`.
        - [ ] **ReconSpider (Scrapy):** `reconspider -d <dominio> -s`. Revisar comentarios en el JSON de salida.
        - [ ] **Photon:** `python photon.py -u <URL> --keys --clone --ninja`.
        - [ ] **GoLinkFinder (GoLF):** `golinkfinder -d <dominio> -s`.
        - [ ] **Hakrawler:** `hakrawler -url <URL> -depth <num>`.
    - [ ] **Qué buscar durante el crawling:**
        - [ ] **Enlaces internos y externos:** Mapear la estructura, descubrir páginas ocultas, identificar relaciones con recursos externos.
        - [ ] **Comentarios:** En HTML, JS, CSS.
        - [ ] **Metadatos:** Títulos de página, descripciones, palabras clave, nombres de autor, fechas.
        - [ ] **Archivos Sensibles:**
            - [ ] Backups: `.bak`, `.old`, `.zip`, `.tar.gz`, `~`.
            - [ ] Archivos de configuración: `web.config`, `settings.php`, `.env`, `config.json`.
            - [ ] Archivos de log: `error_log`, `access_log`.
            - [ ] Archivos con contraseñas o claves API.
            - [ ] **Claves API:** Usar herramientas como `Katana` o buscar patrones comunes de claves. Revisar `securityheaders.com/api/`.
- [ ] **Interceptar Respuestas:**
    - [ ] ¿Se pueden modificar respuestas para eludir restricciones del lado del cliente? (Ej. habilitar botones deshabilitados).

#### Recopilación de Información sobre Dominios y Subdominios

- [ ] **WHOIS:**
    - [ ] `whois <dominio>`: Información de registro, contactos, servidores DNS.
- [ ] **Enumeración DNS:**
    - [ ] **Herramientas básicas:**
        - [ ] `dig <dominio> ANY +noall +answer` / `dig axfr <dominio> @<servidor_dns_autoritativo>` (para transferencia de zona).
        - [ ] `nslookup -type=any <dominio>`.
        - [ ] `host -a <dominio>`.
    - [ ] **Herramientas Avanzadas de Enumeración:**
        - [ ] `dnsenum --noreverse -o subdominios.xml <dominio>`. (WHOIS, Google Dorking, reverse lookup, transferencias de zona).
        - [ ] `fierce --domain <dominio>`.
        - [ ] `dnsrecon -d <dominio> -t axfr` (y otros tipos de enumeración).
        - [ ] `theHarvester -d <dominio> -b all` (emails, subdominios, hosts virtuales).
        - [ ] `amass enum -d <dominio> -active -brute` (combinación de técnicas activas y pasivas).
        - [ ] `subfinder -d <dominio>`.
    - [ ] **Servicios Online:** VirusTotal, crt.sh, Censys, Shodan, SecurityTrails.
- [ ] **Fuzzing Avanzado (ffuf, gobuster, dirsearch, etc.):**
    - [ ] **Fuzzing de Directorios y Archivos:**
        - [ ] `ffuf -w <wordlist_dirs> -u http://<IP_o_dominio>/FUZZ -e .php,.txt,.html,.bak`
        - [ ] `gobuster dir -u http://<IP_o_dominio> -w <wordlist_dirs> -x .php,.txt,.html`
        - [ ] `dirsearch -u http://<IP_o_dominio> -w <wordlist_dirs> -e php,txt,html`
        - [ ] Probar con diferentes wordlists (ej. SecLists: `Discovery/Web-Content/common.txt`, `raft-small-files.txt`, etc.).
        - [ ] Considerar `-H "Header: Value"` si es necesario.
    - [ ] **Fuzzing de Extensiones (Page Fuzzing):** Añadir extensiones comunes (`-e .php,.asp,.aspx,.jsp,.html,.txt,.bak`).
    - [ ] **Fuzzing Recursivo:**
        - [ ] `ffuf -w <wordlist_dirs> -u http://<IP_o_dominio>/FUZZ -recursion -recursion-depth <num>`
        - [ ] `gobuster dir -u http://<IP_o_dominio> -w <wordlist_dirs> -r`
    - [ ] **Fuzzing de Subdominios:**
        - [ ] `ffuf -w <wordlist_subdominios> -u http://FUZZ.<dominio> -H "Host: FUZZ.<dominio>"`
        - [ ] `gobuster dns -d <dominio> -w <wordlist_subdominios>`
    - [ ] **Fuzzing de Vhosts (Hosts Virtuales):**
        - [ ] `ffuf -w <wordlist_vhosts> -u http://<IP_TARGET> -H "Host: FUZZ.<dominio_base>"`
        - [ ] Si se encuentran Vhosts, añadirlos a `/etc/hosts`.
    - [ ] **Fuzzing de Parámetros (GET y POST):**
        - [ ] GET: `ffuf -w <wordlist_params> -u 'http://<URL>?FUZZ=test'`
        - [ ] POST: `ffuf -w <wordlist_params> -u <URL> -X POST -d 'FUZZ=test' -H "Content-Type: application/x-www-form-urlencoded"`
        - [ ] Usar wordlists como `SecLists/Discovery/Web-Content/burp-parameter-names.txt`.
    - [ ] **Fuzzing de Valores de Parámetros:**
        - [ ] Probar valores comunes, payloads de LFI/SQLi/XSS en parámetros conocidos.
    - [ ] **Consejos para Fuzzing:**
        - [ ] Si el fuzzing no tiene éxito, usar un User-Agent aleatorio (ej. `gobuster --random-agent`).
        - [ ] Probar `/.FUZZ` para endpoints ocultos.
        - [ ] Filtrar por códigos de estado (`-fc`, `-mc`), tamaño de respuesta (`-fs`, `-ms`), expresiones regulares (`-fr`, `-mr`).

### Análisis de Peticiones y Respuestas Web

- [ ] **Revisión General de Peticiones/Respuestas:**
    - [ ] Usar DevTools del navegador y Burp Suite/OWASP ZAP para inspeccionar todo el tráfico.
- [ ] **Cabeceras HTTP y Cookies:**
    - [ ] **Cabeceras de Seguridad:**
        - [ ] `Strict-Transport-Security (HSTS)`: ¿Presente? ¿`max-age` adecuado? ¿`includeSubDomains`? ¿`preload`?
        - [ ] `Content-Security-Policy (CSP)`: ¿Presente? ¿Políticas restrictivas y efectivas?
        - [ ] `X-Frame-Options`: ¿`DENY` o `SAMEORIGIN` para prevenir Clickjacking?
        - [ ] `X-Content-Type-Options`: ¿`nosniff`?
        - [ ] `Referrer-Policy`: ¿Política restrictiva como `no-referrer` o `same-origin`?
        - [ ] `Permissions-Policy` (antes `Feature-Policy`): ¿Restringe características del navegador?
        - [ ] `Cache-Control` / `Pragma`: ¿Previene el cacheo de información sensible?
    - [ ] **Cabeceras Informativas:**
        - [ ] `Server`, `X-Powered-By`, `Via`: ¿Revelan demasiada información?
    - [ ] **Cookies (Atributos):**
 