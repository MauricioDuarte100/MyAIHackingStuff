# Clock Work Memory - Writeup

## Descripcion del Reto

> Twillie's "Clockwork Memory" pocketwatch is broken. The memory it holds, a precious story about the Starshard, has been distorted. By reverse-engineering the intricate "clockwork" mechanism of the `pocketwatch.wasm` file, you can discover the source of the distortion and apply the correct "peppermint" key to remember the truth.

**Categoria:** Reversing
**Archivo:** `pocketwatch.wasm`

---

## Analisis

### 1. Identificacion del archivo

```bash
$ file pocketwatch.wasm
pocketwatch.wasm: WebAssembly (wasm) binary module version 0x1 (MVP)
```

El archivo es un modulo WebAssembly binario.

### 2. Descompilacion a formato WAT

Usando `wasm2wat` para obtener el codigo en formato legible:

```bash
$ npx wasm2wat pocketwatch.wasm
```

Resultado relevante:

```wat
(func (;1;) (type 1) (param i32) (result i32)
  (local i32 i32 i32 i32)
  global.get 0
  i32.const 32
  i32.sub
  local.tee 2
  global.set 0
  local.get 2
  i32.const 1262702420          ; <-- Clave almacenada (0x4B4D5754)
  i32.store offset=27 align=1
  loop
    local.get 1
    local.get 2
    i32.add
    local.get 2
    i32.const 27
    i32.add
    local.get 1
    i32.const 3
    i32.and
    i32.add
    i32.load8_u                 ; key[i % 4]
    local.get 1
    i32.load8_u offset=1024     ; encrypted[i]
    i32.xor                     ; XOR
    i32.store8
    local.get 1
    i32.const 1
    i32.add
    local.tee 1
    i32.const 23
    i32.ne
    br_if 0
  end
  ; ... strcmp con el input del usuario
)

(data (;0;) (i32.const 1024) "\1c\1b\010#{0&\0b=p=\0b~0\147\7fs'un>")
```

### 3. Entendiendo el algoritmo

La funcion `check_flag` hace lo siguiente:

1. Almacena una clave de 4 bytes en el stack: `0x4B4D5754` (little-endian: "TWMK")
2. Loop de 0 a 22 (23 iteraciones):
   - `decoded[i] = key[i % 4] XOR encrypted[i]`
3. Compara el buffer decodificado con el input del usuario

### 4. Extraccion de datos encriptados

Del hexdump del archivo, los ultimos 23 bytes son los datos encriptados:

```
1c 1b 01 30 23 7b 30 26 0b 3d 70 3d 0b 7e 30 14 37 7f 73 27 75 6e 3e
```

### 5. Descubriendo la clave correcta

La pista menciona que la memoria esta "distorsionada" y hay que aplicar la clave "peppermint" correcta. El tema del reto es un reloj de bolsillo (pocketwatch/clockwork).

La clave almacenada "TWMK" (`0x4B4D5754`) es incorrecta.

Sabiendo que las flags de HTB empiezan con `HTB{`, podemos derivar la clave correcta:

```python
encrypted = [0x1c, 0x1b, 0x01, 0x30]
flag_prefix = b"HTB{"

# key[i] = encrypted[i] XOR flag[i]
key = bytes([encrypted[i] ^ flag_prefix[i] for i in range(4)])
# Resultado: b"TOCK"
```

**"TOCK"** - como el sonido de un reloj (tick-tock). Tiene sentido con el tema "Clockwork"!

### 6. Descifrando la flag

```python
encrypted = bytes.fromhex('1c1b0130237b30260b3d703d0b7e3014377f7327756e3e')
key = b"TOCK"

flag = bytes([encrypted[i] ^ key[i % 4] for i in range(len(encrypted))])
print(flag.decode())
```

---

## Solucion

```python
#!/usr/bin/env python3
"""
Clock Work Memory - CTF Solution
"""

encrypted = bytes.fromhex('1c1b0130237b30260b3d703d0b7e3014377f7327756e3e')

# Clave incorrecta en el WASM: 0x4B4D5754 = "TWMK"
# Clave correcta derivada: "TOCK" (tick-tock del reloj)
correct_key = b"TOCK"

flag = bytes([encrypted[i] ^ correct_key[i % 4] for i in range(len(encrypted))])
print(f"FLAG: {flag.decode()}")
```

---

## Flag

```
HTB{w4sm_r3v_1s_c00l!!}
```

---

## Notas

- El valor `1262702420` decimal = `0x4B4D5754` hex = `"TWMK"` en little-endian
- La clave correcta `"TOCK"` = `0x544F434B` deberia haber sido el valor almacenado
- El mensaje de la flag: "wasm rev is cool!!" (WebAssembly reversing is cool)
