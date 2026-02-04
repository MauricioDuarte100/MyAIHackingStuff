# Naughty or Nice CTF - Writeup (Flags 1 & 2)

Este documento detalla el proceso paso a paso para obtener las dos primeras flags del reto "Naughty or Nice".

**Target URL:** `http://0dsavguo00i1.ctfhub.io` (Anteriormente: `n7ac0ug0raa8.ctfhub.io`)

---

## Flag 1: Reconocimiento Básico y Archivos de Respaldo

La primera flag se encontró realizando un reconocimiento estándar de archivos y directorios expuestos públicamente.

### Pasos:

1.  **Inspección de `robots.txt`:**
    El primer paso en cualquier aplicación web es revisar el archivo `robots.txt` para ver qué rutas el desarrollador ha intentado ocultar a los motores de búsqueda.

    ```bash
    curl -L http://0dsavguo00i1.ctfhub.io/robots.txt
    ```

    **Salida:**
    ```text
    User-agent: *
    Disallow: /backup
    Disallow: /audit
    ```

2.  **Exploración de la ruta `/backup`:**
    La ruta `/backup` listada en `robots.txt` es un objetivo de alto interés. Al navegar a ella, se encontró el listado de directorios habilitado (Directory Listing).

    ```bash
    curl -L http://0dsavguo00i1.ctfhub.io/backup
    ```

    **Contenido encontrado:**
    - `db.sql` (Dump de la base de datos)
    - `flag.txt`

3.  **Extracción de la Flag:**
    Simplemente descargando el archivo de texto se obtuvo la primera flag.

    ```bash
    curl -L http://0dsavguo00i1.ctfhub.io/backup/flag.txt
    ```

    **Flag 1:**
    ```text
    flag{0d36ca772125c2a0b724cb103edcf157}
    ```

---

## Flag 2: Análisis Estático de Código Fuente (JavaScript)

La segunda flag se encontró analizando el código fuente del cliente (Frontend), específicamente en los archivos JavaScript empaquetados por Vue.js.

### Pasos:

1.  **Identificación del archivo JS principal:**
    Al inspeccionar el código fuente de la página de inicio (`index.html`), se identificó un archivo JavaScript principal cargado como módulo.

    ```html
    <script type="module" crossorigin src="/js/assets/app-CZsgTrKP.js"></script>
    ```

2.  **Descarga y Análisis:**
    Descargamos el archivo para analizarlo en busca de secretos, rutas de API o lógica interesante.

    ```bash
    curl -L http://0dsavguo00i1.ctfhub.io/js/assets/app-CZsgTrKP.js > app.js
    ```

3.  **Búsqueda de Patrones:**
    Dentro del código ofuscado/minificado, buscamos cadenas hexadecimales sospechosas o referencias a "flag". Se encontró una función interesante dentro del componente `AuditPage`.

    **Código encontrado (formateado para lectura):**
    ```javascript
    function f(){
        const d=[
            "6433623433643637633632663530",     // Parte C (Index 0)
            "666c61677b62356663363135303332",   // Parte A (Index 1) - "flag{..."
            "6261387d",                         // Parte D (Index 2) - "...}"
            "64613963646433"                    // Parte B (Index 3)
        ];
        // La lógica reordena el array usando los índices [1, 3, 0, 2]
        const p=[1,3,0,2].map(E=>d[E]).join("");
        // ...luego convierte de Hex a ASCII
    }
    ```

4.  **Reconstrucción y Decodificación:**
    Siguiendo la lógica del array `[1, 3, 0, 2]`:

    1.  Index 1: `666c61677b62356663363135303332`
    2.  Index 3: `64613963646433`
    3.  Index 0: `6433623433643637633632663530`
    4.  Index 2: `6261387d`

    **Cadena Hex completa:**
    `666c61677b623566633631353033326461396364643364336234336436376336326635306261387d`

    **Comando para decodificar:**
    ```bash
    echo "666c61677b623566633631353033326461396364643364336234336436376336326635306261387d" | xxd -r -p
    ```

    **Flag 2:**
    ```text
    flag{b5fc615032da9cdd3d3b43d67c62f50ba8}
    ```
