# CTF "La Trampa" - Writeup Forense

## Información del Archivo

| Campo | Valor |
|-------|-------|
| **Archivo** | `La_Trampa.pcap` |
| **Tamaño** | 42 MB |
| **Paquetes** | 48,877 |
| **Duración** | ~34 minutos (2072 segundos) |
| **Fecha captura** | 2025-06-13 |

---

## FLAGS Encontradas

### FLAG 1: Dirección IP del cliente Windows infectado

**Respuesta:** `10.6.13.133`

**Método de obtención:**

```bash
tshark -r La_Trampa.pcap -q -z conv,ip
```

Se identificó como el host principal con mayor actividad de red. Confirmado como Windows 10 mediante el análisis del User-Agent:

```bash
tshark -r La_Trampa.pcap -Y "http.user_agent contains \"Windows\"" -T fields -e ip.src -e http.user_agent
```

**Evidencia:**
```
10.6.13.133  Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.26100.4202
```

La presencia de PowerShell haciendo peticiones HTTP es un indicador fuerte de infección/malware.

---

### FLAG 2: Dirección MAC del cliente Windows infectado

**Respuesta:** `24:77:03:ac:97:df`

**Método de obtención:**

```bash
tshark -r La_Trampa.pcap -Y "ip.src == 10.6.13.133" -T fields -e eth.src | head -1
```

**Nota:** El prefijo OUI `24:77:03` corresponde al fabricante **Intel Corporation**, típico en tarjetas de red de equipos Windows.

---

### FLAG 3: Nombre de host del cliente Windows infectado

**Respuesta:** `DESKTOP-5AVE44C`

**Método de obtención:**

```bash
tshark -r La_Trampa.pcap -Y "nbns && ip.src == 10.6.13.133" -T fields -e nbns.name | sort -u
```

**Resultado:**
```
DESKTOP-5AVE44C<00> (Workstation/Redirector)
DESKTOP-5AVE44C<20> (Server service)
MASSFRICTION<00> (Workstation/Redirector)
```

El hostname se extrajo del tráfico **NetBIOS Name Service (NBNS)**. El equipo pertenece al dominio/grupo de trabajo `MASSFRICTION`.

---

### FLAG 4: Sitio web sospechoso (punto de entrada)

**Respuesta:** `www.truglomedspa.com`

**Método de obtención:**

```bash
tshark -r La_Trampa.pcap -Y "ip.src == 10.6.13.133 && tls.handshake.type == 1" \
  -T fields -e frame.time_relative -e tls.handshake.extensions_server_name | sort -n | head -50
```

**Análisis:**

Se identificó como el **primer sitio externo no-Microsoft** visitado por el cliente (segundo 49.69), justo antes de que comenzara la cadena de infección hacia los dominios maliciosos.

```bash
tshark -r La_Trampa.pcap -Y "dns.qry.name contains \"truglomedspa\"" \
  -T fields -e frame.time_relative -e dns.qry.name -e dns.a
```

**Resultado:**
```
49.495564  www.truglomedspa.com
49.574912  www.truglomedspa.com  205.174.24.80
```

---

## Cronología de la Infección

| Tiempo (s) | Evento | Dominio/IP |
|------------|--------|------------|
| 0.00 | Inicio de captura, DHCP | - |
| 49.69 | **Visita al sitio sospechoso** | `www.truglomedspa.com` |
| 102.62 | Conexión a dominio malicioso | `dng-microsoftds.com` |
| 113.13 | PowerShell descarga payload | `event-time-microsoft.org` |
| 122.77 | PowerShell descarga payload | `eventdata-microsoft.live` |
| 157.67 | Conexión C2 establecida | `windows.php.net` → `83.137.149.15` |
| 209+ | Comunicación C2 continua | Múltiples dominios |

---

## Indicadores de Compromiso (IOCs)

### Dominios Maliciosos

| Dominio | Descripción |
|---------|-------------|
| `dng-microsoftds.com` | Typosquatting de Microsoft |
| `event-time-microsoft.org` | Descarga de payload PowerShell |
| `eventdata-microsoft.live` | Descarga de payload PowerShell |
| `event-datamicrosoft.live` | C2 communication |
| `windows-msgas.com` | C2 communication |
| `varying-rentals-calgary-predict.trycloudflare.com` | Túnel Cloudflare para C2 |

### Direcciones IP Maliciosas

| IP | Descripción |
|----|-------------|
| `83.137.149.15` | Servidor C2 principal (33 MB exfiltrados) |
| `172.67.146.241` | Cloudflare - hosting de `dng-microsoftds.com` |

### User-Agent Malicioso

```
Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.26100.4202
```

---

## Estadísticas de Red

### Conversación Principal (C2)

```
10.6.13.133 <-> 83.137.149.15
- Frames enviados: 23,281 (33 MB)
- Frames recibidos: 12,204 (754 KB)
- Puerto: 443 (HTTPS)
- Duración: 136 segundos
```

---

## Comandos Útiles Utilizados

```bash
# Ver conversaciones IP
tshark -r La_Trampa.pcap -q -z conv,ip

# Extraer User-Agents
tshark -r La_Trampa.pcap -Y "http.user_agent" -T fields -e ip.src -e http.user_agent

# Ver consultas DNS
tshark -r La_Trampa.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name | sort -u

# Extraer hostnames NBNS
tshark -r La_Trampa.pcap -Y "nbns" -T fields -e nbns.name | sort -u

# Ver conexiones TLS (SNI)
tshark -r La_Trampa.pcap -Y "tls.handshake.type == 1" -T fields -e tls.handshake.extensions_server_name

# Exportar objetos HTTP
tshark -r La_Trampa.pcap -q --export-objects http,/tmp/http_objects

# Ver peticiones HTTP completas
tshark -r La_Trampa.pcap -Y "http.request" -T fields -e http.host -e http.request.uri
```

---

## Conclusiones

1. El cliente Windows (`DESKTOP-5AVE44C` / `10.6.13.133`) visitó el sitio `www.truglomedspa.com`
2. Este sitio redirigió al usuario hacia dominios maliciosos que imitan a Microsoft
3. Se descargó malware mediante PowerShell desde múltiples dominios
4. Se estableció comunicación C2 con el servidor `83.137.149.15`
5. Se exfiltraron aproximadamente **33 MB de datos** hacia el servidor C2

---

*Writeup generado durante el análisis del CTF "La Trampa" de The Hackers Labs*
