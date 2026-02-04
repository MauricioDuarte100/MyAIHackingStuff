# Cómo se encontró la flag

La flag se obtuvo explotando una debilidad en la generación de la clave secreta (JWT secret key) de la aplicación Flask.

## Análisis de la vulnerabilidad

El archivo `app.py` reveló las siguientes líneas clave:

```python
random.seed(f"s3v4r4l_{random.randint(0, 2000)}")
app.secret_key = f"Rem1xKey{random.randint(0, 10**12)}"
```

1.  **Semilla predecible**: La función `random.seed()` se llama con una cadena que incluye un número aleatorio generado por `random.randint(0, 2000)`. Aunque `random` se inicializa por defecto con una semilla más fuerte al inicio del programa, esta línea de `random.seed` *re-siembra* el generador de números pseudoaleatorios Python con una semilla predecible. Esto significa que hay solo 2001 posibles valores para `s3v4r4l_{X}` donde `X` va de 0 a 2000.
2.  **Generación de la clave**: Inmediatamente después de re-sembrar `random`, `app.secret_key` se genera usando `f"Rem1xKey{random.randint(0, 10**12)}"`. Dado que el generador de números aleatorios fue sembrado con un valor predecible en el paso anterior, el `random.randint(0, 10**12)` subsiguiente también producirá una secuencia predecible.

Esto nos permite *predecir* la clave secreta con solo 2001 intentos de fuerza bruta, en lugar de un espacio de búsqueda mucho más grande.

## Pasos para la resolución

1.  **Obtener un token de invitado**: Se realizó una petición `GET` a la URL `https://jwt2025.ctf.cert.unlp.edu.ar/` sin un encabezado `Authorization`. El servidor respondió con un `401 UNAUTHORIZED` y un encabezado `WWW-Authenticate` que contenía un token JWT de invitado (ej: `Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiZ3Vlc3QiLCJpYXQiOjE3NjQ4NTE3NTR9.XMciIX81gfS81NjECritMc-iUT0JZgPBy7jUyn5Dg3k`).

2.  **Fuerza bruta de la clave secreta**:
    *   Se escribió un script en Python (`solve.py`) para replicar el proceso de generación de claves del servidor.
    *   Para cada valor `i` de 0 a 2000:
        *   Se sembró `random` con `f"s3v4r4l_{i}"`.
        *   Se generó un candidato a clave secreta usando `f"Rem1xKey{random.randint(0, 10**12)}"`.
        *   Se intentó decodificar el token de invitado con este candidato a clave.
    *   El script identificó la clave correcta: `Rem1xKey86426418499`.

3.  **Falsificación del token JWT**:
    *   Una vez que se obtuvo la clave secreta, se creó un nuevo payload para el JWT con privilegios elevados: `{"role": "superuser", "user": "admin"}`.
    *   Se codificó este payload usando la clave secreta descubierta (`Rem1xKey86426418499`) y el algoritmo `HS256`.
    *   El token falsificado resultante fue: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic3VwZXJ1c2VyIiwidXNlciI6ImFkbWluIn0.lLSrgzIJUPek_cBhkAzeqtch9c8TTg4gyIuafOrcVG0`.

4.  **Obtención de la Flag**:
    *   Se envió una petición `GET` a `https://jwt2025.ctf.cert.unlp.edu.ar/` con el encabezado `Authorization: Bearer <token_falsificado>`.
    *   El servidor validó el token falsificado y devolvió la flag: `UNLP{R34llY-ur-Us1ng-Ai_for_th1s-B4by-Ch4ll3ng3?}`.
