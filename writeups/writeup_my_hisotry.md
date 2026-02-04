# Writeup - Forense 3

## Flag
```
CYB{find_me_on_ctf}
```

## Archivos proporcionados
- `my_history.pcap` - Archivo de captura de tráfico de red

## Proceso de resolución

### 1. Análisis inicial del PCAP
Se analizó el archivo `my_history.pcap` para identificar el tipo de tráfico capturado.

```bash
tshark -r my_history.pcap -Y "http"
```

Se identificó tráfico HTTP local (127.0.0.1) con múltiples peticiones GET buscando archivos sensibles:
- `/curl.txt` - 404
- `/example.txt` - 404
- `/bash.txt` - 404
- `/.httacess` - 404
- `/log_error` - 404
- `/.access` - 404
- **`/.bash_history` - 200 OK**
- `/.bash` - 404
- `/config.txt` - 404
- `/config.php` - 404

### 2. Extracción del contenido
La petición a `/.bash_history` fue exitosa (HTTP 200). Se extrajo el contenido de la respuesta HTTP:

```bash
tshark -r my_history.pcap --export-objects "http,/tmp/http_export"
```

### 3. Análisis del bash_history
El contenido del archivo `.bash_history` reveló los comandos ejecutados:

```
ls
cd /var/www/html
nano index.php
systemctl status apache2
whoami
uname -a
df -h
free -m

# Comandos del atacante
curl https://web1.xampl3.com/uploads/flag_hidden.txt

echo "the flag is correct?"

exit
```

### 4. Obtención de la flag
El comentario `# Comandos del atacante` indicaba el comando relevante:

```bash
curl https://web1.xampl3.com/uploads/flag_hidden.txt
```

Al acceder a esa URL se obtuvo la flag:
```
CYB{find_me_on_ctf}
```

## Herramientas utilizadas
- `tshark` - Análisis de tráfico de red
- `strings` - Búsqueda de cadenas en archivos binarios
- `xxd` - Conversión hexadecimal
- `curl` - Acceso a la URL descubierta

## Lecciones aprendidas
- Los archivos `.bash_history` pueden exponer comandos sensibles ejecutados por usuarios
- El análisis de tráfico HTTP puede revelar accesos a archivos de configuración
- Es importante proteger archivos sensibles en servidores web
