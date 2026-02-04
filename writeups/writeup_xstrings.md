# Writeup: xstrings (Beginner)

**CTF:** MetaRed / CertUNLP 2025
**Categoría:** Beginner
**Flag:** `UNLP{X0R_4nD_str1nG5}`

## Archivos

- `windows_app.exe.xor` - Ejecutable de Windows cifrado con XOR

## Análisis

Al inspeccionar el archivo con `xxd`, se observan patrones repetitivos:

```
00000000: 0915 c344 4c53 444f 5744 4f53 bbb0 5344  ...DLSDOWDOS..SD
00000010: f753 444f 5344 4f53 044f 5344 4f53 444f  .SDOSDOS.OSDOSDO
00000020: 5344 4f53 444f 5344 4f53 444f 5344 4f53  SDOSDOSDOSDOSDOS
```

El patrón `SDOS`, `DOS` se repite constantemente. Esto indica que el archivo original tenía muchos bytes nulos (0x00), típico de un ejecutable PE.

## Solución

### 1. Identificar la clave XOR

Los ejecutables PE de Windows comienzan con los bytes `MZ` (0x4D, 0x5A).

```python
key_byte0 = 0x09 ^ 0x4D  # = 0x44 = 'D'
key_byte1 = 0x15 ^ 0x5A  # = 0x4F = 'O'
```

La clave es: **`DOS`**

### 2. Descifrar el archivo

```python
key = b'DOS'
with open('windows_app.exe.xor', 'rb') as f:
    data = f.read()

decrypted = bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

with open('windows_app_decrypted.exe', 'wb') as f:
    f.write(decrypted)
```

### 3. Extraer la flag

```bash
strings windows_app_decrypted.exe | grep -i flag
```

**Output:**
```
The flag is: UNLP{X0R_4nD_str1nG5}
```

## Notas

El nombre del reto "xstrings" era una pista directa: **X**OR + **strings**.
