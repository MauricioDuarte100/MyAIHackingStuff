# Writeup: Malware Space 2025 - Reversing Regrets-2

**Desafío**: regrets-2.exe
**Categoría**: Reversing
**Dificultad**: Media-Alta
**Flag**: `m3rry_xmas_4_u@malwarespace.com`

---

## 1. Reconocimiento Inicial

### 1.1 Identificación del Binario

```bash
file regrets-2.exe
```

**Resultado**:
```
regrets-2.exe: PE32+ executable (console) x86-64, for MS Windows, 5 sections
```

Ejecutable Windows de 64 bits. Al estar en Linux, procedí con análisis estático usando radare2 y los archivos descompilados proporcionados (docu1.txt - docu5.txt).

### 1.2 Relación con Regrets-1

Este desafío es la continuación de "Regrets-1" del mismo CTF. La metodología de resolución es similar:
- Sistema de generación de caracteres mediante XOR
- Array de verificación con índices específicos
- Algoritmo de extracción basado en iteración
- Reversión final del string

---

## 2. Análisis de la Función Main

### 2.1 Extracción con Radare2

```bash
r2 -A regrets-2.exe
[0x140012840]> s main
[0x14000cdd0]> pdf > main_full.txt
```

### 2.2 Estructura Identificada

En el código descompilado (docu5.txt) encontré el patrón característico:

```c
v269 = sub_14000BF30();  // Genera carácter 'm'
sub_14000C800((__int64)&v14, &v269);  // Almacena en array
v270 = sub_14000B510();  // Genera control 0
sub_14000C800((__int64)&v14, &v270);  // Almacena en array
// ... se repite 252 veces
```

**Patrón identificado**:
1. Función generadora retorna un valor (carácter o control)
2. Se almacena en el array v14 mediante `sub_14000C800`
3. Se alternan caracteres printables con valores de control (0 o 1)

### 2.3 Array de Verificación

Localicé el array de verificación v277:

```c
v21 = 252;
v277[0] = 238;
v277[1] = 124;
v277[2] = 144;
v277[3] = 178;
v277[4] = 174;
v277[5] = 10;
v277[6] = 250;
v277[7] = 214;
v277[8] = 36;
v277[9] = 0;
v277[10] = 244;
v277[11] = 224;
v277[12] = 136;
v277[13] = 108;
```

**Observaciones**:
- `v21 = 252`: Tamaño total del array de caracteres
- 14 valores de verificación (longitud de la flag)
- Valores entre 0 y 250

---

## 3. Sistema de Generación XOR

### 3.1 Función XOR Base

Todas las funciones generadoras llaman a `sub_140009C60`:

```c
__int64 __fastcall sub_140009C60(__int64 a1, __int64 a2)
{
  return a2 ^ a1;
}
```

### 3.2 Clave XOR

La clave constante es `0xF3A75869DEADBEEF`. Cada función genera un carácter específico:

```c
// sub_14000BF30 genera 'm'
__int64 sub_14000BF30()
{
  return sub_140009C60(0xF3A75869DEADBEEFuLL, 0xF3A75869DEADBE82uLL);
}
// 0xF3A75869DEADBEEF ^ 0xF3A75869DEADBE82 = 0x6D = 'm'

// sub_14000B4E0 genera control 1
__int64 sub_14000B4E0()
{
  return sub_140009C60(0xF3A75869DEADBEEFuLL, 0xF3A75869DEADBEEEuLL);
}
// 0xF3A75869DEADBEEF ^ 0xF3A75869DEADBEEE = 0x01

// sub_14000B510 genera control 0
__int64 sub_14000B510()
{
  return sub_140009C60(0xF3A75869DEADBEEFuLL, 0xF3A75869DEADBEEFuLL);
}
// 0xF3A75869DEADBEEF ^ 0xF3A75869DEADBEEF = 0x00
```

### 3.3 Mapeo Completo de Funciones

Extraje el mapeo de 71 funciones:

```python
func_to_char = {
    "14000bf30": ord('m'),
    "14000b510": 0,         # Control 0
    "14000bed0": ord('k'),
    "14000b4e0": 1,         # Control 1
    "14000c110": ord('y'),
    "14000b6f0": ord('2'),
    "14000c140": ord('z'),
    "14000b720": ord('3'),
    "14000bf60": ord('n'),
    "14000b990": ord('C'),
    "14000bc30": ord('W'),
    "14000bf00": ord('l'),
    # ... 59 funciones más
}
```

---

## 4. Algoritmo de Extracción

### 4.1 El Bucle Principal

```c
v17 = sub_14000CA60(v288) - 1;  // Índice al final
for ( j = 0; j < v21; ++j )     // v21 = 252
{
    sub_14000C6E0((__int64)&v14);
    if ( v17 >= 0 )
    {
        v10 = (_DWORD *)sub_140007100(v288, v17);
        if ( *v10 + 2 == v21 - j )  // Condición clave
        {
            v15 = *(_BYTE *)sub_14000B4C0(&v14);
            std::string::operator+=(v289, v15);
            --v17;
        }
    }
}
```

### 4.2 Análisis de la Condición

```
*v10 + 2 == v21 - j
*v10 + 2 == 252 - j
*v10 == 250 - j
```

Para cada valor en v277:
- Si `v277[k] == 250 - j`, se extrae `chars[v277[k]]`

### 4.3 Cálculo del Orden de Extracción

| v277[k] | valor | j = 250 - valor | chars[valor] |
|---------|-------|-----------------|--------------|
| v277[6] | 250   | j = 0           | 'u'          |
| v277[10]| 244   | j = 6           | '_'          |
| v277[0] | 238   | j = 12          | '4'          |
| v277[11]| 224   | j = 26          | '_'          |
| v277[7] | 214   | j = 36          | 's'          |
| v277[3] | 178   | j = 72          | 'a'          |
| v277[4] | 174   | j = 76          | 'm'          |
| v277[2] | 144   | j = 106         | 'x'          |
| v277[12]| 136   | j = 114         | '_'          |
| v277[1] | 124   | j = 126         | 'y'          |
| v277[13]| 108   | j = 142         | 'r'          |
| v277[8] | 36    | j = 214         | 'r'          |
| v277[5] | 10    | j = 240         | '3'          |
| v277[9] | 0     | j = 250         | 'm'          |

**String extraído**: `u_4_samx_yrr3m`

### 4.4 Reversión Final

```c
v286 = (_QWORD *)sub_14000B180((__int64)v289, (__int64)v294);
v11 = (_QWORD *)sub_140009830((__int64)v289, (__int64)v295);
sub_140005330(*v11, *v286);  // std::reverse
```

**Flag final**: `m3rry_xmas_4_u`

---

## 5. Script de Solución

```python
#!/usr/bin/env python3
"""Solver for regrets-2 CTF challenge"""
import re

# Mapeo función -> carácter
func_to_char = {
    "14000bf30": ord('m'), "14000b510": 0, "14000bed0": ord('k'),
    "14000b4e0": 1, "14000c110": ord('y'), "14000b6f0": ord('2'),
    "14000c140": ord('z'), "14000b720": ord('3'), "14000bf60": ord('n'),
    "14000b990": ord('C'), "14000bc30": ord('W'), "14000bf00": ord('l'),
    "14000b7b0": ord('6'), "14000bba0": ord('R'), "14000b930": ord('@'),
    "14000b570": ord('$'), "14000be70": ord('i'), "14000ba80": ord('J'),
    "14000c0b0": ord('w'), "14000bff0": ord('r'), "14000bb40": ord('O'),
    "14000b6c0": ord('0'), "14000b5a0": ord('%'), "14000bab0": ord('K'),
    "14000c1d0": ord('}'), "14000bae0": ord('M'), "14000bc60": ord('X'),
    "14000bc90": ord('Y'), "14000be40": ord('h'), "14000b630": ord('*'),
    "14000bd80": ord('`'), "14000bbd0": ord('T'), "14000b960": ord('A'),
    "14000bf90": ord('o'), "14000bd50": ord('_'), "14000b750": ord('4'),
    "14000c170": ord('{'), "14000bd20": ord(']'), "14000bc00": ord('U'),
    "14000b5d0": ord("'"), "14000b8d0": ord('>'), "14000bfc0": ord('q'),
    "14000c050": ord('t'), "14000b9c0": ord('D'), "14000ba50": ord('I'),
    "14000c080": ord('u'), "14000b7e0": ord('7'), "14000b600": ord('('),
    "14000b840": ord(';'), "14000b540": ord('#'), "14000be10": ord('f'),
    "14000b8a0": ord('='), "14000c0e0": ord('x'), "14000b780": ord('5'),
    "14000bcc0": ord('['), "14000bcf0": ord('\\'), "14000bea0": ord('j'),
    "14000bb70": ord('P'), "14000b810": ord(':'), "14000b690": ord('/'),
    "14000bdb0": ord('a'), "14000b870": ord('<'), "14000b900": ord('?'),
    "14000c1a0": ord('|'), "14000c200": ord('~'), "14000c020": ord('s'),
    "14000b9f0": ord('G'), "14000bb10": ord('N'), "14000ba20": ord('H'),
    "14000bde0": ord('c'), "14000b660": ord(','),
}

# Leer disassembly
with open("main_full.txt", "r") as f:
    content = f.read()

# Extraer llamadas a funciones (excluyendo c800)
pattern = r'call fcn\.([0-9a-f]+)'
matches = re.findall(pattern, content)

# Construir array
full_array = []
for addr in matches:
    if addr in func_to_char and addr != "14000c800":
        full_array.append(func_to_char[addr])

# Array de verificación
v277 = [238, 124, 144, 178, 174, 10, 250, 214, 36, 0, 244, 224, 136, 108]
v21 = 252

# Calcular orden de extracción
extractions = []
for val in v277:
    j = 250 - val
    if 0 <= j < v21:
        extractions.append((j, val))
extractions.sort(key=lambda x: x[0])

# Extraer caracteres
flag_chars = []
for j, char_pos in extractions:
    if 0 <= char_pos < len(full_array):
        val = full_array[char_pos]
        if val > 1:
            flag_chars.append(chr(val))

# Revertir
flag = ''.join(flag_chars)[::-1]
print(f"FLAG: {flag}@malwarespace.com")
```

**Ejecución**:
```
$ python3 solve_regrets2.py
FLAG: m3rry_xmas_4_u@malwarespace.com
```

---

## 6. Diagrama del Flujo

```
[252 llamadas a funciones] → [XOR con 0xF3A75869DEADBEEF] → [Array de 252 elementos]
                                                                      ↓
                                                            [Índices en v277]
                                                                      ↓
                                                            [Algoritmo j-loop]
                                                            [if val+2 == 252-j]
                                                                      ↓
                                                            [14 caracteres]
                                                                      ↓
                                                              [Reversión]
                                                                      ↓
                                                          m3rry_xmas_4_u
                                                                      ↓
                                                      [Formato @malwarespace.com]
                                                                      ↓
                                              m3rry_xmas_4_u@malwarespace.com
```

---

## 7. Comparación con Regrets-1

| Aspecto | Regrets-1 | Regrets-2 |
|---------|-----------|-----------|
| Tamaño array (v21) | 356 | 252 |
| Elementos flag | 22 | 14 |
| Clave XOR | 0xF3A75869DEADBEEF | 0xF3A75869DEADBEEF |
| Condición | val + 2 == 356 - j | val + 2 == 252 - j |
| Flag | D0N7_T0UCH_MY_W00L_BR0 | m3rry_xmas_4_u |
| Formato | ALP{...} | ...@malwarespace.com |

---

## 8. Herramientas Utilizadas

- **radare2**: Desensamblado de la función main
- **IDA Pro / Hex-Rays**: Archivos descompilados (docu1.txt - docu5.txt)
- **Python 3**: Script de solución
- **grep/regex**: Extracción de patrones

---

## 9. Lecciones Aprendidas

1. **Reutilización de técnicas**: La metodología de regrets-1 aplicó directamente
2. **Identificación de patrones**: El patrón (char, control) fue clave
3. **Análisis estático**: Posible sin ejecutar el binario
4. **XOR simple**: La ofuscación se basa en volumen, no complejidad

---

### Flag Final
```
m3rry_xmas_4_u@malwarespace.com
```

**Autor**: p0mb3r0
**Fecha**: 2025
**CTF**: Malware Space 2025
**Categoría**: Reversing
