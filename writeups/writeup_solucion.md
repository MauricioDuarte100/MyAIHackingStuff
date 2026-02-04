# Writeup: Pong - VM became something
## MalwareSpace CTF 2025

**Autor:** Análisis realizado con Antigravity Code
**Fecha:** 17 de Diciembre de 2025
**Categoría:** Reversing / Network Forensics
**Dificultad:** Media-Alta

---

## 1. Descripción del Reto

> **Pong - VM became something. Find a way to understand it.**

Se nos proporciona un archivo `malware.pcapng` que contiene tráfico de red capturado. El objetivo es realizar ingeniería inversa para extraer y descifrar una flag oculta.

---

## 2. Reconocimiento Inicial

### 2.1 Análisis del PCAP

Al abrir el archivo con Wireshark o tshark, observamos que contiene principalmente tráfico **ICMP** (paquetes ping/pong). Esto es consistente con el nombre del reto "Pong".

```bash
tshark -r malware.pcapng -Y "icmp" | head -20
```

Identificamos comunicación entre:
- **Víctima:** `192.168.176.133`
- **C2 (Command & Control):** `192.168.176.1`

### 2.2 Extracción de Datos ICMP

Los paquetes ICMP Echo Request contienen datos en su payload. Extraemos estos datos:

```bash
tshark -r malware.pcapng -Y "icmp.type == 8" -T fields -e data.data > /tmp/icmp_data.txt
```

Esto nos da **132 líneas** de datos hexadecimales de 8 bytes cada una (instrucciones de una VM).

---

## 3. Análisis de la Máquina Virtual

### 3.1 Estructura de las Instrucciones

Cada instrucción tiene 8 bytes en formato Little-Endian:

```
[OPCODE] [ARG1] [VALOR] [ARG2] [ADDR_LO] [ADDR_HI] [EXTRA_LO] [EXTRA_HI]
```

### 3.2 Opcodes Identificados

| Opcode | Nombre | Descripción |
|--------|--------|-------------|
| 0x01 | INIT_MEM | Inicializa un byte en memoria |
| 0x0C | OPEN | Abre un archivo |
| 0x0A | READ | Lee datos de archivo |
| 0x03 | WRITE | Escribe a stdout |
| 0x20 | MOVE | Lógica de movimiento (Pong) |
| 0x12 | CRYPTO | Operación criptográfica |
| 0x18 | LOOP | Control de flujo |
| 0xFF | END | Fin de ejecución |

### 3.3 Mapa de Memoria Reconstruido

Analizando las instrucciones `0x01` (INIT_MEM), reconstruimos la memoria inicial:

| Dirección | Contenido | Descripción |
|-----------|-----------|-------------|
| 0x0FC8 | `key.mspace\0` | Nombre del archivo (11 bytes) |
| 0x0F2C | 37 bytes | **CodeString** |
| 0x0F90 | 37 bytes | **Ciphertext** (datos cifrados) |
| 0x01F4 | Buffer | Buffer de salida |

---

## 4. Extracción de Datos Clave

### 4.1 CodeString (0x0F2C - 37 bytes)

```
Hex: 633f3f414141242f2f26322f2f6b646f6f6f6f242f312632325f32242d6c416d6e5f6b6579
ASCII: c??AAA$//&2//kdoooo$/1&22_2$-lAmn_key
```

### 4.2 Ciphertext (0x0F90 - 37 bytes)

```
Hex: 637b245a695263366b0e0c073073632b476d4760362c613c204c1a27322a45457a40287e62
ASCII: c{$ZiRc6k...0sc+GmG`6,a< L'2*EEz@(~b
```

### 4.3 Keyfile (0x0FC8)

```
ASCII: key.mspace
```

---

## 5. Análisis Criptográfico

### 5.1 Hipótesis Inicial (Incorrecta)

Basándonos en el análisis previo del reporte, se pensaba que el algoritmo era:

```
Delta = KeyFile[key_bounce[i]] - CodeString[code_bounce[i]]
Flag[i] = Ciphertext[i] + Delta
```

Donde los índices seguían un patrón de "rebote" tipo Pong. Sin embargo, después de extensas pruebas, esta hipótesis no producía resultados válidos.

### 5.2 Descubrimiento del Algoritmo Real

Después de probar múltiples combinaciones, encontramos que el algoritmo es mucho más simple:

**Paso 1:** XOR entre Ciphertext y CodeString
```python
xor_base = bytes([ciphertext[i] ^ codestring[i] for i in range(37)])
```

Resultado intermedio:
```
Hex: 00441b1b2813471944283e281f18074428022844191d470e121328031f460428141f431b1b
Decimal: [0, 68, 27, 27, 40, 19, 71, 25, 68, 40, 62, 40, 31, 24, 7, 68, 40, 2, 40, 68, 25, 29, 71, 14, 18, 19, 40, 3, 31, 70, 4, 40, 20, 31, 67, 27, 27]
```

**Paso 2:** XOR con la constante 0x77 (119 decimal, carácter 'w')
```python
flag = bytes([b ^ 0x77 for b in xor_base])
```

### 5.3 El Algoritmo Final

```python
flag[i] = ciphertext[i] ^ codestring[i] ^ 0x77
```

O de forma equivalente:
```python
flag = (ciphertext XOR codestring) XOR 0x77
```

---

## 6. Solución

### 6.1 Script de Descifrado

```python
#!/usr/bin/env python3
"""
Solución: Pong - VM became something
MalwareSpace CTF 2025
"""

# Datos extraídos del PCAP
ciphertext = bytes.fromhex(
    '637b245a695263366b0e0c073073632b'
    '476d4760362c613c204c1a27322a4545'
    '7a40287e62'
)

codestring = bytes.fromhex(
    '633f3f414141242f2f26322f2f6b646f'
    '6f6f6f242f312632325f32242d6c416d'
    '6e5f6b6579'
)

# Clave XOR
XOR_KEY = 0x77  # 119 decimal, carácter 'w'

# Descifrado
flag = bytes([
    ciphertext[i] ^ codestring[i] ^ XOR_KEY
    for i in range(37)
])

print(f"Flag: {flag.decode('ascii')}")
```

### 6.2 Resultado

```
Flag: w3ll_d0n3_I_hop3_u_3nj0yed_th1s_ch4ll
```

**Traducción (Leetspeak):** "well done I hope you enjoyed this chall"

---

## 7. Verificación Byte a Byte

| Pos | Cipher | Code | XOR Base | ^ 0x77 | Flag |
|-----|--------|------|----------|--------|------|
| 0 | 0x63 (c) | 0x63 (c) | 0x00 | 0x77 | **w** |
| 1 | 0x7b ({) | 0x3f (?) | 0x44 | 0x33 | **3** |
| 2 | 0x24 ($) | 0x3f (?) | 0x1b | 0x6c | **l** |
| 3 | 0x5a (Z) | 0x41 (A) | 0x1b | 0x6c | **l** |
| 4 | 0x69 (i) | 0x41 (A) | 0x28 | 0x5f | **_** |
| 5 | 0x52 (R) | 0x41 (A) | 0x13 | 0x64 | **d** |
| 6 | 0x63 (c) | 0x24 ($) | 0x47 | 0x30 | **0** |
| 7 | 0x36 (6) | 0x2f (/) | 0x19 | 0x6e | **n** |
| ... | ... | ... | ... | ... | ... |

---

## 8. Posibles Formatos de Flag

Dependiendo del formato del CTF, la flag podría ser:

1. **Raw:** `w3ll_d0n3_I_hop3_u_3nj0yed_th1s_ch4ll`
2. **mspace{}:** `mspace{w3ll_d0n3_I_hop3_u_3nj0yed_th1s_ch4ll}`
3. **flag{}:** `flag{w3ll_d0n3_I_hop3_u_3nj0yed_th1s_ch4ll}`

---

## 9. Lecciones Aprendidas

### 9.1 Misdirection
El reto incluía múltiples pistas falsas:
- El nombre "Pong" sugería un algoritmo de rebote complejo
- Las instrucciones de la VM (MOVE, CRYPTO, LOOP) sugerían una lógica elaborada
- El análisis previo mencionaba "bouncing patterns" y algoritmos dinámicos

### 9.2 Solución Real
La solución real era un simple **XOR de tres valores**:
- Ciphertext (datos cifrados)
- CodeString (clave parcial)
- Constante 0x77 (clave final)

### 9.3 Metodología
1. Siempre probar las operaciones más simples primero (XOR, ADD, SUB)
2. Buscar patrones en los datos extraídos
3. No dejarse llevar completamente por las pistas del reto

---

## 10. Herramientas Utilizadas

- **tshark/Wireshark:** Análisis de PCAP
- **Python 3:** Scripts de análisis y descifrado
- **xxd/hexdump:** Análisis hexadecimal

---

## 11. Referencias

- Archivo original: `malware.pcapng`
- Datos recuperados: `recovered_output.txt`
- Análisis previo: `reporte_analisis_pong.md`

---

## Flag Final

```
w3ll_d0n3_I_hop3_u_3nj0yed_th1s_ch4ll
```

**GG! Well played!** 🎮🏓
