# El Ángel Exterminador - Writeup

## Categoría
Crypto (Beginner)

## Descripción
Se proporciona un archivo `flag.png.xor` que contiene una imagen PNG cifrada con XOR.

## Solución

### Paso 1: Análisis del archivo cifrado

Examinamos los primeros bytes del archivo cifrado:

```
00000000: dc1e 0217 3f3a 283f 2155 4e41 197a 7460
```

### Paso 2: Conocer la cabecera PNG

Todos los archivos PNG comienzan con una cabecera fija de 8 bytes:

```
89 50 4E 47 0D 0A 1A 0A
```

### Paso 3: Obtener la clave XOR

Dado que XOR es reversible (`A XOR B = C` implica `A XOR C = B`), podemos obtener la clave haciendo XOR entre los bytes cifrados y la cabecera PNG conocida:

```python
png_header = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
xor_bytes = bytes([0xdc, 0x1e, 0x02, 0x17, 0x3f, 0x3a, 0x28, 0x3f])

key = bytes([a ^ b for a, b in zip(xor_bytes, png_header)])
print(key)  # b'UNLP2025'
```

La clave parcial es `UNLP2025`. Probando variaciones, la clave completa es: **`UNLP2025!`**

### Paso 4: Descifrar el archivo

```python
def xor_decrypt(input_path, output_path, key):
    key_bytes = key.encode('utf-8')
    key_len = len(key_bytes)

    with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
        data = f_in.read()
        decrypted_data = bytearray()

        for i in range(len(data)):
            decrypted_data.append(data[i] ^ key_bytes[i % key_len])

        f_out.write(decrypted_data)

xor_decrypt("flag.png.xor", "flag.png", "UNLP2025!")
```

### Paso 5: Obtener la flag

Al abrir la imagen descifrada, se muestra un poster de la película "El Ángel Exterminador" de Luis Buñuel con la flag en la parte superior.

## Flag

```
UNLP{f4th3r0fsurrealism!}
```

## Notas

- La flag hace referencia a Luis Buñuel como el "padre del surrealismo" en el cine
- El nombre del reto "El Ángel Exterminador" es una de sus películas más famosas (1962)
- La clave `UNLP2025!` probablemente hace referencia a la Universidad Nacional de La Plata y el año del CTF
