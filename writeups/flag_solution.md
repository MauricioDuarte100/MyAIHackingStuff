Aquí está la documentación rápida de cómo se encontró la flag:

### Reto CTF: Fragmentos de Flag Escondidos

**Objetivo:** Recuperar 3 fragmentos de flag ocultos de la página web `https://ucabrera.github.io/teg_chall/`.

---

**Pasos Realizados:**

1.  **Obtener el código fuente principal:**
    Se utilizó `curl` para descargar el `index.html` de la página principal:
    ```bash
    curl -s https://ucabrera.github.io/teg_chall/ > page.html
    ```

2.  **Análisis de `page.html` (index.html):**
    Al revisar el contenido de `page.html`, se encontró el primer fragmento en la etiqueta `meta` de descripción:
    ```html
    <meta name="description" content="Explore our image collection in this interactive gallery.UNLP{1_dOnt_like_">
    ```
    *   **Fragmento 1:** `UNLP{1_dOnt_like_`

3.  **Identificación de recursos externos:**
    Se observó que `page.html` enlazaba a `style.css` y `main.js`. Estos archivos fueron descargados:
    ```bash
    curl -s https://ucabrera.github.io/teg_chall/style.css > style.css
    curl -s https://ucabrera.github.io/teg_chall/main.js > main.js
    ```

4.  **Análisis de `style.css`:**
    Al inspeccionar `style.css`, se encontró el segundo fragmento oculto en un comentario CSS dentro de un bloque `@media`:
    ```css
    /* Responsive desing the_TEG_map_|_prefer_ */
    @media (max-width: 768px) {
        /* ... */
    }
    ```
    *   **Fragmento 2:** `the_TEG_map_|_prefer_`

5.  **Análisis de `main.js`:**
    El archivo `main.js` contenía directamente el tercer fragmento:
    ```
    the_Bor3d_Grid}
    ```
    *   **Fragmento 3:** `the_Bor3d_Grid}`

6.  **Ensamblaje de la Flag:**
    Combinando los tres fragmentos en el orden encontrado se obtiene la flag completa:

    `UNLP{1_dOnt_like_` + `the_TEG_map_|_prefer_` + `the_Bor3d_Grid}`

    **Flag Final:**
    `UNLP{1_dOnt_like_the_TEG_map_|_prefer_the_Bor3d_Grid}`

---