# 📝 Writeup: Zydra Web3 (PHP-Redis + Orange Tsai Bypass)

## Descripción del Reto
El reto presentaba un panel de monitoreo de red (`admin.php`) protegido por autenticación Basic Auth. El objetivo era obtener la flag oculta en la infraestructura de red interna.

## Análisis de Vulnerabilidades

### 1. Inyección de Argumentos en `curl` (SSRF)
El script `admin.php` permitía pasar opciones arbitrarias al comando `curl` mediante el parámetro `opt`.
*   **Vulnerabilidad:** No se saneaban opciones peligrosas como `-o` (output) y `-K` (config file).
*   **Impacto:** Permite escribir archivos arbitrarios en el sistema (`-o`) y leer configuraciones que habilitan protocolos internos como `dict://`.

### 2. Evasión de Autenticación (Apache Confusion Attack)
El servidor utilizaba una directiva `Files "admin.php"` en Apache para proteger el acceso. Sin embargo, mediante la técnica de **Orange Tsai (Confusion Attack)**, pudimos eludir esta protección.
*   **Payload:** `/admin.php%3fooo.php`
*   **Mecánica:** Apache permite el acceso porque el nombre del archivo solicitado (`admin.php?ooo.php`) no coincide exactamente con `admin.php`. No obstante, la regla `FilesMatch ".+\.php$"` sí coincide, enviando la petición a PHP-FPM, el cual ejecuta `admin.php` ignorando el resto de la URI.

### 3. Miscelánea: Redis Info Disclosure
Redis interno tiene comandos administrativos deshabilitados (`CONFIG`, `SET`), pero el comando `GET` está permitido. La flag se encontraba en la clave `flag`.

---

## Cadena de Explotación (Exploit Chain)

1.  **Preparación:** Subir una configuración de `curl` a dpaste con el contenido: `url = "dict://redis:6379/GET:flag"`.
2.  **Descarga:** Usar el bypass de autenticación e inyectar `opt=-o` para descargar dicha configuración a `/tmp/`.
3.  **Ejecución:** Usar el bypass nuevamente e inyectar `opt=-K` apuntando al archivo descargado.
4.  **Resultado:** La respuesta de `admin.php` muestra la salida de Redis con la flag.

**Flag:**
`RE:CTF{0r4ng3_1z_my_g04t_plu5_u_d0nt_n33d_g0ph3r}`
