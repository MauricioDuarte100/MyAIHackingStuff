# Solución del Reto: Algo de temporada 🎄

## 1. Análisis Inicial
Al explorar el directorio del reto, encontramos los siguientes archivos:
- `README.txt`: Indica que el cifrado es sencillo, reversible con el mismo proceso y no utiliza algoritmos complejos.
- `nota_de_santa.txt`: Menciona que usa "ejemplos" y a veces cambia letras por números.
- `navidad_con_xampl3.txt`: El nombre de este archivo es la pista clave: **xampl3** (una versión "leet" de *example*).
- `regalo.enc.txt`: Contiene el mensaje cifrado en formato hexadecimal: `SECRET_REDACTED_BY_ANTIGRAVITY1b1908521c1c`.

## 2. Identificación del Algoritmo
El `README.txt` menciona que "con el mismo proceso se puede volver al estado original". Esta es una característica clásica del cifrado **XOR**. Si aplicamos XOR al texto cifrado con la misma clave, recuperamos el texto original.

La clave sugerida por los nombres de los archivos y las notas es `xampl3`.

## 3. Descifrado
Utilizando un script de Python, realizamos la operación XOR entre la cadena hexadecimal y la clave `xampl3`:

```python
data = bytes.fromhex('SECRET_REDACTED_BY_ANTIGRAVITY1b1908521c1c')
key = b'xampl3'
decoded = ''.join(chr(data[i] ^ key[i % len(key)]) for i in range(len(data)))
print(decoded)
```

## 4. Resultado
Al ejecutar el script, obtenemos el mensaje original:
**FLAG{SantaEncriptaNavidad}**
