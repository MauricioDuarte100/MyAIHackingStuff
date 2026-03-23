# Writeup Detallado: Pong - VM became something
## MalwareSpace CTF 2025

---

# PARTE 1: RECONOCIMIENTO Y EXTRACCIÓN DE DATOS

---

## 1.1 Archivos Proporcionados

Al descargar el reto, encontramos los siguientes archivos:

```
pong/
├── malware.pcapng      # Captura de tráfico de red
└── recovered_output.txt # Salida de debug de la VM (opcional)
```

El archivo principal es `malware.pcapng`, una captura de paquetes de red en formato PCAPNG (Packet Capture Next Generation).

---

## 1.2 Análisis Inicial del PCAP

### Paso 1: Abrir el archivo con tshark

Primero, examinamos qué tipo de tráfico contiene el archivo:

```bash
tshark -r malware.pcapng -q -z io,phs
```

**Salida:**
```
Protocol Hierarchy Statistics
├── eth
│   └── ip
│       └── icmp    ← Principalmente tráfico ICMP
```

El tráfico es predominantemente **ICMP** (Internet Control Message Protocol), comúnmente usado para comandos `ping`.

### Paso 2: Examinar los paquetes ICMP

```bash
tshark -r malware.pcapng -Y "icmp" | head -10
```

**Salida:**
```
1   0.000000 192.168.176.133 → 192.168.176.1 ICMP Echo (ping) request
2   0.000123 192.168.176.1 → 192.168.176.133 ICMP Echo (ping) reply
3   0.001000 192.168.176.133 → 192.168.176.1 ICMP Echo (ping) request
...
```

Observamos:
- **Origen (víctima):** `192.168.176.133`
- **Destino (C2):** `192.168.176.1`
- Los paquetes son Echo Request (tipo 8) y Echo Reply (tipo 0)

### Paso 3: Contar los paquetes

```bash
tshark -r malware.pcapng -Y "icmp.type == 8" | wc -l
```

**Resultado:** `132` paquetes Echo Request

Esto significa que hay **132 instrucciones** de la VM ocultas en los paquetes ICMP.

---

## 1.3 Extracción de los Datos Ocultos

### Paso 4: Extraer el payload de cada paquete ICMP

Los datos están en el campo `data.data` de cada paquete ICMP Echo Request:

```bash
tshark -r malware.pcapng -Y "icmp.type == 8" -T fields -e data.data > /tmp/icmp_data.txt
```

### Paso 5: Examinar los datos extraídos

```bash
head -20 /tmp/icmp_data.txt
```

**Salida:**
```
01006b000fc80000
010065000fc90000
010079000fca0000
01002e000fcb0000
01006d000fcc0000
010073000fcd0000
010070000fce0000
010061000fcf0000
010063000fd00000
010065000fd10000
010000000fd20000
010063000f2c0001
01003f000f2d0001
01003f000f2e0001
010041000f2f0001
010041000f300001
010041000f310001
010024000f320001
01002f000f330001
01002f000f340001
```

Cada línea contiene **8 bytes** en hexadecimal = **16 caracteres hex**.

---

# PARTE 2: ANÁLISIS DE LA MÁQUINA VIRTUAL

---

## 2.1 Estructura de las Instrucciones

Cada instrucción de 8 bytes tiene el siguiente formato:

```
Byte 0: OPCODE (código de operación)
Byte 1: ARG1 (primer argumento)
Byte 2: VALOR (valor a escribir/usar)
Byte 3: ARG2 (segundo argumento)
Byte 4-5: DIRECCIÓN (Little-Endian)
Byte 6-7: EXTRA (datos adicionales)
```

### Ejemplo de decodificación:

Tomemos la primera línea: `01006b000fc80000`

```
01  00  6b  00  0f  c8  00  00
│   │   │   │   │   │   │   │
│   │   │   │   │   │   └───┴── Extra: 0x0000
│   │   │   │   └───┴────────── Dirección: 0xC80F → 0x0FC8 (Little-Endian)
│   │   │   └────────────────── ARG2: 0x00
│   │   └────────────────────── VALOR: 0x6b = 107 = 'k'
│   └────────────────────────── ARG1: 0x00
└────────────────────────────── OPCODE: 0x01 (INIT_MEM)
```

**Interpretación:** Escribir el byte `0x6b` ('k') en la dirección de memoria `0x0FC8`.

---

## 2.2 Identificación de Opcodes

Analizando todas las instrucciones, identificamos los siguientes opcodes:

| Opcode | Hex | Nombre | Función |
|--------|-----|--------|---------|
| 0x01 | 01 | INIT_MEM | Inicializa un byte en memoria |
| 0x02 | 02 | UNKNOWN | Operación desconocida |
| 0x03 | 03 | WRITE | Escribe a stdout/buffer |
| 0x05 | 05 | UNKNOWN | Operación desconocida |
| 0x07 | 07 | UNKNOWN | Operación desconocida |
| 0x0A | 0a | READ | Lee de archivo/buffer |
| 0x0C | 0c | OPEN | Abre un archivo |
| 0x0E | 0e | UNKNOWN | Operación desconocida |
| 0x12 | 12 | CRYPTO | Operación criptográfica |
| 0x18 | 18 | LOOP | Control de bucle |
| 0x1A | 1a | UNKNOWN | Operación desconocida |
| 0x1C | 1c | UNKNOWN | Operación desconocida |
| 0x20 | 20 | MOVE | Movimiento tipo "Pong" |
| 0xFF | ff | END | Fin de ejecución |

---

## 2.3 Reconstrucción del Mapa de Memoria

### Paso 6: Extraer todas las instrucciones INIT_MEM (0x01)

Las instrucciones que empiezan con `01` escriben datos en memoria. Analizamos los patrones de direcciones:

**Región 0x0FC8-0x0FD2 (11 bytes): Nombre del archivo**
```
Línea 1:  01006b000fc80000 → mem[0x0FC8] = 0x6b = 'k'
Línea 2:  010065000fc90000 → mem[0x0FC9] = 0x65 = 'e'
Línea 3:  010079000fca0000 → mem[0x0FCA] = 0x79 = 'y'
Línea 4:  01002e000fcb0000 → mem[0x0FCB] = 0x2e = '.'
Línea 5:  01006d000fcc0000 → mem[0x0FCC] = 0x6d = 'm'
Línea 6:  010073000fcd0000 → mem[0x0FCD] = 0x73 = 's'
Línea 7:  010070000fce0000 → mem[0x0FCE] = 0x70 = 'p'
Línea 8:  010061000fcf0000 → mem[0x0FCF] = 0x61 = 'a'
Línea 9:  010063000fd00000 → mem[0x0FD0] = 0x63 = 'c'
Línea 10: 010065000fd10000 → mem[0x0FD1] = 0x65 = 'e'
Línea 11: 010000000fd20000 → mem[0x0FD2] = 0x00 = '\0'
```

**Resultado:** `key.mspace\0` (nombre del archivo que la VM intenta abrir)

---

**Región 0x0F2C-0x0F50 (37 bytes): CodeString**

```
Línea 12: 010063000f2c0001 → mem[0x0F2C] = 0x63 = 'c'
Línea 13: 01003f000f2d0001 → mem[0x0F2D] = 0x3f = '?'
Línea 14: 01003f000f2e0001 → mem[0x0F2E] = 0x3f = '?'
Línea 15: 010041000f2f0001 → mem[0x0F2F] = 0x41 = 'A'
Línea 16: 010041000f300001 → mem[0x0F30] = 0x41 = 'A'
Línea 17: 010041000f310001 → mem[0x0F31] = 0x41 = 'A'
Línea 18: 010024000f320001 → mem[0x0F32] = 0x24 = '$'
Línea 19: 01002f000f330001 → mem[0x0F33] = 0x2f = '/'
Línea 20: 01002f000f340001 → mem[0x0F34] = 0x2f = '/'
Línea 21: 010026000f350001 → mem[0x0F35] = 0x26 = '&'
Línea 22: 010032000f360001 → mem[0x0F36] = 0x32 = '2'
Línea 23: 01002f000f370001 → mem[0x0F37] = 0x2f = '/'
Línea 24: 01002f000f380001 → mem[0x0F38] = 0x2f = '/'
Línea 25: 01006b000f390001 → mem[0x0F39] = 0x6b = 'k'
Línea 26: 010064000f3a0001 → mem[0x0F3A] = 0x64 = 'd'
Línea 27: 01006f000f3b0001 → mem[0x0F3B] = 0x6f = 'o'
Línea 28: 01006f000f3c0001 → mem[0x0F3C] = 0x6f = 'o'
Línea 29: 01006f000f3d0001 → mem[0x0F3D] = 0x6f = 'o'
Línea 30: 01006f000f3e0001 → mem[0x0F3E] = 0x6f = 'o'
Línea 31: 010024000f3f0001 → mem[0x0F3F] = 0x24 = '$'
Línea 32: 01002f000f400001 → mem[0x0F40] = 0x2f = '/'
Línea 33: 010031000f410001 → mem[0x0F41] = 0x31 = '1'
Línea 34: 010026000f420001 → mem[0x0F42] = 0x26 = '&'
Línea 35: 010032000f430001 → mem[0x0F43] = 0x32 = '2'
Línea 36: 010032000f440001 → mem[0x0F44] = 0x32 = '2'
Línea 37: 01005f000f450001 → mem[0x0F45] = 0x5f = '_'
Línea 38: 010032000f460001 → mem[0x0F46] = 0x32 = '2'
Línea 39: 010024000f470001 → mem[0x0F47] = 0x24 = '$'
Línea 40: 01002d000f480001 → mem[0x0F48] = 0x2d = '-'
Línea 41: 01006c000f490001 → mem[0x0F49] = 0x6c = 'l'
Línea 42: 010041000f4a0001 → mem[0x0F4A] = 0x41 = 'A'
Línea 43: 01006d000f4b0001 → mem[0x0F4B] = 0x6d = 'm'
Línea 44: 01006e000f4c0001 → mem[0x0F4C] = 0x6e = 'n'
Línea 45: 01005f000f4d0001 → mem[0x0F4D] = 0x5f = '_'
Línea 46: 01006b000f4e0001 → mem[0x0F4E] = 0x6b = 'k'
Línea 47: 010065000f4f0001 → mem[0x0F4F] = 0x65 = 'e'
Línea 48: 010079000f500001 → mem[0x0F50] = 0x79 = 'y'
```

**CodeString completo (37 bytes):**
```
Hex: SECRET_REDACTED_BY_ANTIGRAVITY2f312632325f32242d6c416d6e5f6b6579
ASCII: c??AAA$//&2//kdoooo$/1&22_2$-lAmn_key
```

---

**Región 0x0F90-0x0FB4 (37 bytes): Ciphertext**

```
Línea 49: 010063000f900001 → mem[0x0F90] = 0x63 = 'c'
Línea 50: 01007b000f910001 → mem[0x0F91] = 0x7b = '{'
Línea 51: 010024000f920001 → mem[0x0F92] = 0x24 = '$'
Línea 52: 01005a000f930001 → mem[0x0F93] = 0x5a = 'Z'
Línea 53: 010069000f940001 → mem[0x0F94] = 0x69 = 'i'
Línea 54: 010052000f950001 → mem[0x0F95] = 0x52 = 'R'
Línea 55: 010063000f960001 → mem[0x0F96] = 0x63 = 'c'
Línea 56: 010036000f970001 → mem[0x0F97] = 0x36 = '6'
Línea 57: 01006b000f980001 → mem[0x0F98] = 0x6b = 'k'
Línea 58: 01000e000f990001 → mem[0x0F99] = 0x0e = (no imprimible)
Línea 59: 01000c000f9a0001 → mem[0x0F9A] = 0x0c = (no imprimible)
Línea 60: 010007000f9b0001 → mem[0x0F9B] = 0x07 = (no imprimible)
Línea 61: 010030000f9c0001 → mem[0x0F9C] = 0x30 = '0'
Línea 62: 010073000f9d0001 → mem[0x0F9D] = 0x73 = 's'
Línea 63: 010063000f9e0001 → mem[0x0F9E] = 0x63 = 'c'
Línea 64: 01002b000f9f0001 → mem[0x0F9F] = 0x2b = '+'
Línea 65: 010047000fa00001 → mem[0x0FA0] = 0x47 = 'G'
Línea 66: 01006d000fa10001 → mem[0x0FA1] = 0x6d = 'm'
Línea 67: 010047000fa20001 → mem[0x0FA2] = 0x47 = 'G'
Línea 68: 010060000fa30001 → mem[0x0FA3] = 0x60 = '`'
Línea 69: 010036000fa40001 → mem[0x0FA4] = 0x36 = '6'
Línea 70: 01002c000fa50001 → mem[0x0FA5] = 0x2c = ','
Línea 71: 010061000fa60001 → mem[0x0FA6] = 0x61 = 'a'
Línea 72: 01003c000fa70001 → mem[0x0FA7] = 0x3c = '<'
Línea 73: 010020000fa80001 → mem[0x0FA8] = 0x20 = ' '
Línea 74: 01004c000fa90001 → mem[0x0FA9] = 0x4c = 'L'
Línea 75: 01001a000faa0001 → mem[0x0FAA] = 0x1a = (no imprimible)
Línea 76: 010027000fab0001 → mem[0x0FAB] = 0x27 = '\''
Línea 77: 010032000fac0001 → mem[0x0FAC] = 0x32 = '2'
Línea 78: 01002a000fad0001 → mem[0x0FAD] = 0x2a = '*'
Línea 79: 010045000fae0001 → mem[0x0FAE] = 0x45 = 'E'
Línea 80: 010045000faf0001 → mem[0x0FAF] = 0x45 = 'E'
Línea 81: 01007a000fb00001 → mem[0x0FB0] = 0x7a = 'z'
Línea 82: 010040000fb10001 → mem[0x0FB1] = 0x40 = '@'
Línea 83: 010028000fb20001 → mem[0x0FB2] = 0x28 = '('
Línea 84: 01007e000fb30001 → mem[0x0FB3] = 0x7e = '~'
Línea 85: 010062000fb40001 → mem[0x0FB4] = 0x62 = 'b'
```

**Ciphertext completo (37 bytes):**
```
Hex: SECRET_REDACTED_BY_ANTIGRAVITY362c613c204c1a27322a45457a40287e62
```

---

# PARTE 3: DESCIFRADO DE LA FLAG

---

## 3.1 Resumen de Datos Extraídos

Tenemos tres elementos clave:

| Nombre | Dirección | Tamaño | Contenido Hex |
|--------|-----------|--------|---------------|
| Keyfile | 0x0FC8 | 11 bytes | `6b65792e6d737061636500` |
| CodeString | 0x0F2C | 37 bytes | `SECRET_REDACTED_BY_ANTIGRAVITY2f312632325f32242d6c416d6e5f6b6579` |
| Ciphertext | 0x0F90 | 37 bytes | `SECRET_REDACTED_BY_ANTIGRAVITY362c613c204c1a27322a45457a40287e62` |

---

## 3.2 Proceso de Descifrado Paso a Paso

### Paso 7: Convertir los datos a bytes en Python

```python
# Datos extraídos del PCAP
ciphertext_hex = "SECRET_REDACTED_BY_ANTIGRAVITY362c613c204c1a27322a45457a40287e62"
codestring_hex = "SECRET_REDACTED_BY_ANTIGRAVITY2f312632325f32242d6c416d6e5f6b6579"

# Convertir de hexadecimal a bytes
ciphertext = bytes.fromhex(ciphertext_hex)
codestring = bytes.fromhex(codestring_hex)

print(f"Ciphertext ({len(ciphertext)} bytes): {ciphertext}")
print(f"CodeString ({len(codestring)} bytes): {codestring}")
```

**Salida:**
```
Ciphertext (37 bytes): b"c{$ZiRc6k\x0e\x0c\x070sc+GmG`6,a< L\x1a'2*EEz@(~b"
CodeString (37 bytes): b'c??AAA$//&2//kdoooo$/1&22_2$-lAmn_key'
```

---

### Paso 8: Calcular XOR entre Ciphertext y CodeString

La operación XOR (^) compara cada bit de dos valores:
- Si los bits son iguales → resultado = 0
- Si los bits son diferentes → resultado = 1

```python
# XOR byte a byte
xor_result = []
for i in range(37):
    xor_byte = ciphertext[i] ^ codestring[i]
    xor_result.append(xor_byte)

xor_result = bytes(xor_result)
print(f"XOR Result: {xor_result.hex()}")
print(f"Como lista: {list(xor_result)}")
```

**Cálculo detallado para los primeros bytes:**

```
Posición 0:
  Ciphertext[0] = 0x63 = 0110 0011
  CodeString[0] = 0x63 = 0110 0011
  XOR           = 0x00 = 0000 0000  ← Los bits son iguales

Posición 1:
  Ciphertext[1] = 0x7b = 0111 1011
  CodeString[1] = 0x3f = 0011 1111
  XOR           = 0x44 = 0100 0100

Posición 2:
  Ciphertext[2] = 0x24 = 0010 0100
  CodeString[2] = 0x3f = 0011 1111
  XOR           = 0x1b = 0001 1011

... (y así para los 37 bytes)
```

**Resultado del XOR:**
```
Hex: SECRET_REDACTED_BY_ANTIGRAVITY191d470e121328031f460428141f431b1b
Lista: [0, 68, 27, 27, 40, 19, 71, 25, 68, 40, 62, 40, 31, 24, 7, 68, 40, 2, 40, 68, 25, 29, 71, 14, 18, 19, 40, 3, 31, 70, 4, 40, 20, 31, 67, 27, 27]
```

---

### Paso 9: Encontrar la clave XOR final

Probamos XOR del resultado intermedio con diferentes valores (0-255):

```python
# Probar todas las claves posibles de un byte
for key in range(256):
    result = bytes([b ^ key for b in xor_result])

    # Verificar si el resultado es ASCII imprimible
    try:
        decoded = result.decode('ascii')
        # Contar caracteres imprimibles
        printable_count = sum(1 for c in decoded if c.isprintable())

        if printable_count >= 30 and decoded[0].isalpha():
            print(f"Clave {key} (0x{key:02x}, '{chr(key) if 32 <= key < 127 else '?'}'): {decoded}")
    except:
        pass
```

**Resultado clave encontrado con key = 119 (0x77, 'w'):**

```
Clave 119 (0x77, 'w'): w3ll_d0n3_I_hop3_u_3nj0yed_th1s_ch4ll
```

---

### Paso 10: Verificación completa byte a byte

```python
XOR_KEY = 0x77  # 119 en decimal, 'w' en ASCII

print("Pos | Cipher | Code   | XOR    | ^0x77  | Flag")
print("----|--------|--------|--------|--------|-----")

flag_bytes = []
for i in range(37):
    c = ciphertext[i]
    s = codestring[i]
    xor_val = c ^ s
    final = xor_val ^ XOR_KEY
    flag_bytes.append(final)

    c_char = chr(c) if 32 <= c < 127 else '?'
    s_char = chr(s) if 32 <= s < 127 else '?'
    f_char = chr(final) if 32 <= final < 127 else '?'

    print(f" {i:2} | 0x{c:02x} {c_char} | 0x{s:02x} {s_char} | 0x{xor_val:02x}   | 0x{final:02x}   | {f_char}")

flag = bytes(flag_bytes).decode('ascii')
print(f"\nFLAG: {flag}")
```

**Tabla de verificación completa:**

```
Pos | Cipher | Code   | XOR    | ^0x77  | Flag
----|--------|--------|--------|--------|-----
  0 | 0x63 c | 0x63 c | 0x00   | 0x77   | w
  1 | 0x7b { | 0x3f ? | 0x44   | 0x33   | 3
  2 | 0x24 $ | 0x3f ? | 0x1b   | 0x6c   | l
  3 | 0x5a Z | 0x41 A | 0x1b   | 0x6c   | l
  4 | 0x69 i | 0x41 A | 0x28   | 0x5f   | _
  5 | 0x52 R | 0x41 A | 0x13   | 0x64   | d
  6 | 0x63 c | 0x24 $ | 0x47   | 0x30   | 0
  7 | 0x36 6 | 0x2f / | 0x19   | 0x6e   | n
  8 | 0x6b k | 0x2f / | 0x44   | 0x33   | 3
  9 | 0x0e ? | 0x26 & | 0x28   | 0x5f   | _
 10 | 0x0c ? | 0x32 2 | 0x3e   | 0x49   | I
 11 | 0x07 ? | 0x2f / | 0x28   | 0x5f   | _
 12 | 0x30 0 | 0x2f / | 0x1f   | 0x68   | h
 13 | 0x73 s | 0x6b k | 0x18   | 0x6f   | o
 14 | 0x63 c | 0x64 d | 0x07   | 0x70   | p
 15 | 0x2b + | 0x6f o | 0x44   | 0x33   | 3
 16 | 0x47 G | 0x6f o | 0x28   | 0x5f   | _
 17 | 0x6d m | 0x6f o | 0x02   | 0x75   | u
 18 | 0x47 G | 0x6f o | 0x28   | 0x5f   | _
 19 | 0x60 ` | 0x24 $ | 0x44   | 0x33   | 3
 20 | 0x36 6 | 0x2f / | 0x19   | 0x6e   | n
 21 | 0x2c , | 0x31 1 | 0x1d   | 0x6a   | j
 22 | 0x61 a | 0x26 & | 0x47   | 0x30   | 0
 23 | 0x3c < | 0x32 2 | 0x0e   | 0x79   | y
 24 | 0x20   | 0x32 2 | 0x12   | 0x65   | e
 25 | 0x4c L | 0x5f _ | 0x13   | 0x64   | d
 26 | 0x1a ? | 0x32 2 | 0x28   | 0x5f   | _
 27 | 0x27 ' | 0x24 $ | 0x03   | 0x74   | t
 28 | 0x32 2 | 0x2d - | 0x1f   | 0x68   | h
 29 | 0x2a * | 0x6c l | 0x46   | 0x31   | 1
 30 | 0x45 E | 0x41 A | 0x04   | 0x73   | s
 31 | 0x45 E | 0x6d m | 0x28   | 0x5f   | _
 32 | 0x7a z | 0x6e n | 0x14   | 0x63   | c
 33 | 0x40 @ | 0x5f _ | 0x1f   | 0x68   | h
 34 | 0x28 ( | 0x6b k | 0x43   | 0x34   | 4
 35 | 0x7e ~ | 0x65 e | 0x1b   | 0x6c   | l
 36 | 0x62 b | 0x79 y | 0x1b   | 0x6c   | l

FLAG: w3ll_d0n3_I_hop3_u_3nj0yed_th1s_ch4ll
```

---

# PARTE 4: SOLUCIÓN FINAL

---

## 4.1 Script Completo de Solución

```python
#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════╗
║  Solución: Pong - VM became something                         ║
║  MalwareSpace CTF 2025                                        ║
║  Categoría: Reversing / Network Forensics                     ║
╚═══════════════════════════════════════════════════════════════╝
"""

def main():
    # ═══════════════════════════════════════════════════════════
    # DATOS EXTRAÍDOS DEL PCAP (instrucciones INIT_MEM de la VM)
    # ═══════════════════════════════════════════════════════════

    # Ciphertext: 37 bytes en dirección 0x0F90
    ciphertext = bytes.fromhex(
        "637b245a695263366b0e0c073073632b"
        "476d4760362c613c204c1a27322a4545"
        "7a40287e62"
    )

    # CodeString: 37 bytes en dirección 0x0F2C
    codestring = bytes.fromhex(
        "633f3f414141242f2f26322f2f6b646f"
        "6f6f6f242f312632325f32242d6c416d"
        "6e5f6b6579"
    )

    # ═══════════════════════════════════════════════════════════
    # CLAVE XOR FINAL
    # ═══════════════════════════════════════════════════════════

    XOR_KEY = 0x77  # 119 decimal = 'w' ASCII

    # ═══════════════════════════════════════════════════════════
    # ALGORITMO DE DESCIFRADO
    # ═══════════════════════════════════════════════════════════
    #
    # flag[i] = ciphertext[i] XOR codestring[i] XOR 0x77
    #
    # Equivalente a:
    # flag = (ciphertext XOR codestring) XOR 0x77
    #
    # ═══════════════════════════════════════════════════════════

    flag_bytes = []
    for i in range(37):
        decrypted_byte = ciphertext[i] ^ codestring[i] ^ XOR_KEY
        flag_bytes.append(decrypted_byte)

    flag = bytes(flag_bytes).decode('ascii')

    # ═══════════════════════════════════════════════════════════
    # RESULTADO
    # ═══════════════════════════════════════════════════════════

    print("=" * 60)
    print("FLAG ENCONTRADA")
    print("=" * 60)
    print()
    print(f"  {flag}")
    print()
    print("=" * 60)
    print()
    print("Significado (Leetspeak → Español):")
    print("  'well done I hope you enjoyed this chall'")
    print("  'bien hecho, espero que hayas disfrutado este reto'")
    print()
    print("Posibles formatos para el CTF:")
    print(f"  • Raw:     {flag}")
    print(f"  • mspace:  mspace{{{flag}}}")
    print(f"  • flag:    flag{{{flag}}}")

    return flag

if __name__ == "__main__":
    main()
```

---

## 4.2 Ejecución del Script

```bash
$ python3 solve.py
SECRET_REDACTED_BY_ANTIGRAVITY====================
FLAG ENCONTRADA
SECRET_REDACTED_BY_ANTIGRAVITY====================

  w3ll_d0n3_I_hop3_u_3nj0yed_th1s_ch4ll

SECRET_REDACTED_BY_ANTIGRAVITY====================

Significado (Leetspeak → Español):
  'well done I hope you enjoyed this chall'
  'bien hecho, espero que hayas disfrutado este reto'

Posibles formatos para el CTF:
  • Raw:     w3ll_d0n3_I_hop3_u_3nj0yed_th1s_ch4ll
  • mspace:  mspace{w3ll_d0n3_I_hop3_u_3nj0yed_th1s_ch4ll}
  • flag:    flag{w3ll_d0n3_I_hop3_u_3nj0yed_th1s_ch4ll}
```

---

# PARTE 5: ANÁLISIS POST-MORTEM

---

## 5.1 El Nombre "Pong" y la Misdirection

El reto se llamaba "Pong" y contenía instrucciones de VM como `MOVE` (0x20) que sugerían un algoritmo de "rebote" similar al juego Pong. Esto era **misdirection intencional**.

Las instrucciones de la VM incluían:
- `200005ff` - MOVE con parámetro 0xff (-1 en complemento a 2)
- `200106ff` - MOVE con parámetro 0xff

Esto sugería que los índices "rebotaban" entre límites, pero el cifrado real era mucho más simple.

## 5.2 Por Qué Funciona el XOR con 0x77

La clave `0x77` (119) es el carácter **'w'**, que es la primera letra de la flag `w3ll...`. Esto no es coincidencia:

```
XOR_base[0] = cipher[0] ^ code[0] = 0x63 ^ 0x63 = 0x00
flag[0] = 0x00 ^ 0x77 = 0x77 = 'w'
```

El primer byte del ciphertext y codestring son iguales (`'c'`), lo que resulta en 0x00 después del XOR. Al aplicar XOR con 0x77, obtenemos directamente la clave, que es también el primer carácter de la flag.

## 5.3 Lecciones Aprendidas

1. **Empezar simple:** Antes de implementar algoritmos complejos, probar operaciones básicas (XOR, ADD, SUB).

2. **Buscar patrones:** El XOR de dos cadenas del mismo tamaño a menudo revela la clave.

3. **No confiar ciegamente en las pistas:** El nombre "Pong" y las instrucciones MOVE eran distracciones.

4. **Fuerza bruta inteligente:** Probar las 256 posibles claves XOR de un byte es trivial y efectivo.

---

# FLAG FINAL

```
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│   w3ll_d0n3_I_hop3_u_3nj0yed_th1s_ch4ll                    │
│                                                             │
│   Traducción: "well done I hope you enjoyed this chall"     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

**GG! Reto completado. - by p0mb3r0** 🎮🏓
