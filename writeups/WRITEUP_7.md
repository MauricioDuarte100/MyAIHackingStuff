# Writeup - notime.py CTF Challenge

## Flag
```
ALP{th3re_1s_n0_t1m3_4_th15!!!}
```

## Análisis

### 1. Deserialización del código
El archivo `notime.py` contiene código Python ofuscado usando `marshal`. Al deserializarlo se revela la función `custom_hash`:

```python
import marshal
data = bytes.fromhex("e3000000...")
code_obj = marshal.loads(data)
dis.dis(code_obj)  # Ver el bytecode
```

### 2. Algoritmo identificado

La función `custom_hash` realiza:
1. Rellena el mensaje con `\x00` hasta múltiplo de 16 bytes
2. Usa una clave XOR de 2 bytes (número entre 100-999)
3. Divide en bloques de 16 bytes
4. Aplica XOR con la clave a cada bloque
5. Convierte cada bloque en 2 hashes de 64 bits

### 3. Reversing

Con 4 hashes en `result.txt` → 2 bloques → 32 bytes totales

**Script de fuerza bruta:**
```python
target_hashes = [4820632610269180120, 7418891870308414453,
                 8618603916866510046, 7753851154656362154]

for xor_key in range(100, 1000):
    key_bytes = xor_key.to_bytes(2, 'big')
    message = bytearray()

    # Reconstruir bloques desde los hashes
    for i in range(0, len(target_hashes), 2):
        block = bytearray()
        # hash1 → primeros 8 bytes
        for j in range(8):
            block.append((target_hashes[i] >> (56 - j*8)) & 0xFF)
        # hash2 → siguientes 8 bytes
        for j in range(8):
            block.append((target_hashes[i+1] >> (56 - j*8)) & 0xFF)

        # Revertir XOR
        for k in range(16):
            block[k] ^= key_bytes[k % 2]

        message.extend(block)

    # Verificar si es UTF-8 válido
    try:
        flag = message.decode('utf-8').rstrip('\x00')
        if '@' in flag or '{' in flag:
            print(f"XOR Key: {xor_key} → {flag}")
    except:
        pass
```

### 4. Resultado

**Clave XOR:** 938
**Flag:** `ALP{th3re_1s_n0_t1m3_4_th15!!!}`

Verificado ejecutando el código original con la flag encontrada, generando los mismos hashes.
