# Solución del Reto de Criptografía

Para resolver este reto, seguimos los siguientes pasos:

## 1. Análisis de los archivos
Primero, revisamos el contenido de los archivos proporcionados:
- `mensaje.txt`: Contenía la cadena `RkxBR3tDUllQVE9fRVNfRkFDSUx9`.
- `pista.txt`: Mencionaba que el mensaje no estaba cifrado, sino "traducido a un idioma que usa letras, números y a veces '='".

## 2. Identificación del formato
La descripción en la pista coincide perfectamente con la codificación **Base64**, la cual utiliza un alfabeto de 64 caracteres (A-Z, a-z, 0-9, +, /) y a menudo incluye `=` como relleno (padding).

## 3. Decodificación
Procedimos a decodificar la cadena usando la herramienta de línea de comandos `base64`:

```bash
echo "RkxBR3tDUllQVE9fRVNfRkFDSUx9" | base64 -d
```

## 4. Resultado
Al decodificar la cadena, obtuvimos la flag:
**FLAG{CRYPTO_ES_FACIL}**
