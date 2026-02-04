# Solución del Reto: Sombras en el Tablero

## 1. Análisis Inicial
Al explorar el directorio, encontramos tres archivos:
- `board.US.png`: Una imagen de un tablero de ajedrez (el sufijo `.US` sugiere terminología en inglés).
- `cipher.txt`: Contiene una cadena hexadecimal: `0003130c3d0c1a0e151c0d0d091d1936`.
- `README.txt`: Proporciona pistas sobre la lógica del reto.

## 2. Descifrando las Pistas
El archivo `README.txt` dice:
> "Una sola pieza, dos amenazas a la vez. ♕ / ♖"

En ajedrez, cuando una sola pieza ataca a dos o más piezas enemigas simultáneamente, se le llama **Doble ataque** o, más comúnmente en inglés, **FORK**.

## 3. Estrategia de Descifrado
Dado que el mensaje en `cipher.txt` parece un hash o una cadena cifrada y la pista apunta a una palabra específica, se probó un cifrado **XOR** simple utilizando la palabra **"FORK"** como clave repetitiva.

### Script de resolución (Python):
```python
cipher_hex = '0003130c3d0c1a0e151c0d0d091d1936'
key = 'FORK'

cipher_bytes = bytes.fromhex(cipher_hex)
key_bytes = key.encode()

# XOR bit a bit con la clave repetida
decrypted = bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(cipher_bytes)])
print(decrypted.decode())
```

## 4. Resultado
Al ejecutar el XOR con la clave `FORK`, obtenemos el mensaje en texto claro:

**Flag:** `FLAG{CHESS_FORK}`
