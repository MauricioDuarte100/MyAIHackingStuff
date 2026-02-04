# Writeup: Black Alpaca CTF - Reversing Regrets

**Desafío**: regrets.exe
**Categoría**: Reversing
**Dificultad**: Media-Alta
**Flag**: `ALP{D0N7_T0UCH_MY_W00L_BR0}`

---

## 1. Reconocimiento Inicial

### 1.1 Identificación del Binario

Primero identifiqué el tipo de archivo:

```bash
file regrets.exe
```

**Resultado**:
```
regrets.exe: PE32+ executable (console) x86-64, for MS Windows, 5 sections
```

Es un ejecutable de Windows de 64 bits. Al no poder ejecutarlo directamente en Linux, procedí al análisis estático usando los archivos descompilados proporcionados.

### 1.2 Análisis de Archivos Descompilados

El directorio contenía varios archivos de código descompilado:
- `doc1.txt` - Código descompilado (Binary Ninja format)
- `docu2.txt` - Código descompilado (Hex-Rays format)
- `docu3.txt`, `doc4.txt`, `docu5.txt`, `docu6.txt` - Más código descompilado

---

## 2. Búsqueda de Pistas Iniciales

### 2.1 Strings Importantes

Busqué strings relevantes en los archivos:

```bash
grep -ri "flag\|alpaca\|password" *.txt
```

**Hallazgo clave**:
```
docu2.txt:7198:  sub_140001390((__int64)&qword_14004D600, "[----- Black Alpaca ---- ]\nPassword: ");
```

Esto indica que el programa:
1. Muestra un banner "Black Alpaca"
2. Solicita una contraseña
3. Probablemente valida y devuelve algo

### 2.2 Localización de la Función Main

Busqué la función main:

```bash
grep -n "^int.*main\|^uint64_t main" doc1.txt docu2.txt
```

**Encontrado en**:
- `docu2.txt:6057` - Formato Hex-Rays
- `doc1.txt:5790` - Formato Binary Ninja

---

## 3. Análisis de la Función Main

### 3.1 Estructura General

Al examinar el código de `main()` encontré un patrón repetitivo:

```c
int32_t var_150c = sub_14000bfc0();
sub_14000c9e0(&var_1ac0, &var_150c);
int32_t var_1508 = sub_14000b4e0();
sub_14000c9e0(&var_1ac0, &var_1508);
// ... se repite 356 veces
```

**Patrón identificado**:
1. Se llama a una función que retorna un entero
2. Ese valor se agrega a un vector/array mediante `sub_14000c9e0`
3. Este patrón se repite 356 veces exactamente

### 3.2 Array de Verificación

Más adelante en el código encontré:

```c
v21 = 356;
v381[0] = 10;
v381[1] = 306;
v381[2] = 312;
v381[3] = 94;
v381[4] = 260;
v381[5] = 140;
v381[6] = 314;
v381[7] = 354;
v381[8] = 236;
v381[9] = 228;
v381[10] = 244;
v381[11] = 80;
v381[12] = 70;
v381[13] = 184;
v381[14] = 20;
v381[15] = 192;
v381[16] = 130;
v381[17] = 332;
v381[18] = 334;
v381[19] = 60;
v381[20] = 52;
v381[21] = 232;
```

**Observaciones**:
- Array de 22 elementos
- Valores entre 10 y 354
- `v21 = 356` parece ser el tamaño total del array de caracteres

---

## 4. Análisis del Sistema de XOR

### 4.1 Descubrimiento de la Función XOR

Busqué las definiciones de las funciones que se llamaban repetidamente:

```bash
grep -A 3 "sub_14000B4E0\(\)" docu2.txt
```

**Resultado**:
```c
__int64 sub_14000B4E0()
{
  return sub_140009C60(0xF3A75869DEADBEEFuLL, 0xF3A75869DEADBEEEuLL);
}
```

Todas las funciones llamaban a `sub_140009C60` con dos parámetros.

### 4.2 Identificación de la Operación XOR

Busqué la definición de `sub_140009C60`:

```c
__int64 __fastcall sub_140009C60(__int64 a1, __int64 a2)
{
  return a2 ^ a1;
}
```

**¡Era simplemente XOR!**

Cada función retorna: `0xF3A75869DEADBEEF ^ valor_específico`

### 4.3 Extracción de Todos los Valores XOR

Creé un script para extraer todas las funciones y sus valores:

```python
#!/usr/bin/env python3
import re

with open('docu2.txt', 'r') as f:
    content = f.read()

# Buscar todas las funciones que hacen XOR
pattern = r'(__int64 sub_14000[A-F0-9]{4}\(\)\s*\{\s*return sub_140009C60\(0x([0-9A-F]+)uLL, 0x([0-9A-F]+)uLL\);)'
matches = re.findall(pattern, content, re.IGNORECASE)

XOR_KEY = 0xF3A75869DEADBEEF
func_map = {}

for match in matches:
    func_name = re.search(r'sub_14000[A-F0-9]{4}', match[0]).group()
    val1 = int(match[1], 16)
    val2 = int(match[2], 16)
    xor_result = val1 ^ val2
    func_map[func_name.lower()] = xor_result
    print(f"{func_name}: {chr(xor_result) if 32 <= xor_result < 127 else '?'}")
```

**Resultado**: Mapeé 81 funciones a sus caracteres correspondientes:
- `sub_14000B4E0` → `0x01` (carácter de control)
- `sub_14000B510` → `0x00` (null)
- `sub_14000B540` → `0x22` (")
- `sub_14000B720` → `0x30` (0)
- `sub_14000B750` → `0x31` (1)
- `sub_14000B9F0` → `0x42` (B)
- ... etc.

---

## 5. Construcción del Array de Caracteres

### 5.1 Extracción del Orden de Llamadas

Necesitaba saber el orden exacto de las 356 llamadas a funciones:

```bash
grep -E "int32_t var_[0-9a-f]+ = sub_14000[a-f0-9]+\(\)" doc1.txt | \
  grep -oE "sub_14000[a-f0-9]+" > all_funcs.txt
```

**Verificación**:
```bash
wc -l all_funcs.txt
# Output: 356 all_funcs.txt
```

¡Exacto! 356 llamadas, coincidiendo con `v21 = 356`.

### 5.2 Script de Construcción del Array

```python
#!/usr/bin/env python3
import json

# Cargar el mapeo de funciones
with open('func_map.json', 'r') as f:
    func_map = json.load(f)

# Cargar el orden de llamadas
with open('all_funcs.txt', 'r') as f:
    function_calls = [line.strip().lower() for line in f]

# Construir array de caracteres
chars = []
for func in function_calls:
    if func in func_map:
        chars.append(func_map[func])
    else:
        chars.append(ord('?'))

print(f"Array completo: {len(chars)} caracteres")
```

---

## 6. Análisis del Algoritmo de Extracción

### 6.1 El Bucle de Extracción

En el código encontré este bucle crítico:

```c
v20 = sub_14000CC40(v392) - 1;  // Índice al final del array
for ( j = 0; j < v21 - 2; ++j )
{
    sub_14000C8C0((__int64)&v14);
    v10 = (_DWORD *)sub_140007100(v392, v20);
    if ( *v10 + 2 == v21 - j )  // Condición clave!
    {
        v15 = *(_BYTE *)sub_14000B4C0(&v14);
        std::string::operator+=(v393, v15);
        --v20;
    }
}
```

**Análisis de la condición**:
```
*v10 + 2 == v21 - j
```

Donde:
- `v21 = 356`
- `j` va de 0 a 353 (v21 - 2)
- `*v10` es un valor del array `v392`

### 6.2 Descifrando el Algoritmo

Para cada `j`, el algoritmo busca:
```
valor + 2 = 356 - j
valor = 354 - j
```

Entonces:
- j=0 → busca valor=354
- j=1 → busca valor=353
- j=2 → busca valor=352
- ...
- j=353 → busca valor=1

### 6.3 Correlación con v381

Los valores en `v381` son exactamente algunos de estos "valores buscados":
- v381[7] = 354 (se encuentra en j=0)
- v381[18] = 334 (se encuentra en j=20)
- v381[17] = 332 (se encuentra en j=22)
- ... etc.

### 6.4 Script de Correlación

```python
v381 = [10, 306, 312, 94, 260, 140, 314, 354, 236, 228, 244,
        80, 70, 184, 20, 192, 130, 332, 334, 60, 52, 232]
v21 = 356

# Para cada j, encontrar si el valor buscado está en v381
matches = []
for j in range(v21 - 2):
    needed_val = v21 - j - 2
    if needed_val in v381:
        idx_in_v381 = v381.index(needed_val)
        char_pos = v381[idx_in_v381]
        matches.append((j, needed_val, char_pos))

# Ordenar por j para obtener el orden de extracción
matches.sort(key=lambda x: x[0])

# Extraer caracteres
flag = ""
for j, val, char_pos in matches:
    char = chr(chars[char_pos])
    flag += char
    print(f"j={j:3d}: chars[{char_pos:3d}] = '{char}'")
```

**Resultado**:
```
j=  0: chars[354] = '0'
j= 20: chars[334] = 'R'
j= 22: chars[332] = 'B'
j= 40: chars[314] = '_'
j= 42: chars[312] = 'L'
j= 48: chars[306] = '0'
j= 94: chars[260] = '0'
j=110: chars[244] = 'W'
j=118: chars[236] = '_'
j=122: chars[232] = 'Y'
j=126: chars[228] = 'M'
j=162: chars[192] = '_'
j=170: chars[184] = 'H'
j=214: chars[140] = 'C'
j=224: chars[130] = 'U'
j=260: chars[ 94] = '0'
j=274: chars[ 80] = 'T'
j=284: chars[ 70] = '_'
j=294: chars[ 60] = '7'
j=302: chars[ 52] = 'N'
j=334: chars[ 20] = '0'
j=344: chars[ 10] = 'D'

Flag extraída: 0RB_L00W_YM_HCU0T_7N0D
```

---

## 7. Reversión de la Flag

### 7.1 Identificación de la Reversión

En el código, después del bucle de extracción, encontré:

```c
v390 = (_QWORD *)sub_14000B180((__int64)v393, (__int64)v398);
v11 = (_QWORD *)sub_140009830((__int64)v393, (__int64)v399);
sub_140005330(*v11, *v390);  // Probablemente std::reverse
```

La función `sub_140005330` probablemente es `std::reverse()`.

### 7.2 Reversión Manual

```python
flag = "0RB_L00W_YM_HCU0T_7N0D"
flag_reversed = flag[::-1]
print(f"Flag invertida: {flag_reversed}")
```

**Resultado**:
```
D0N7_T0UCH_MY_W00L_BR0
```

¡Tiene sentido! "DON'T TOUCH MY WOOL BRO" (¡No toques mi lana, hermano!)

---

## 8. Formato de la Flag

### 8.1 Búsqueda en el Binario

Para encontrar el formato correcto de la flag, analicé strings en el ejecutable:

```bash
strings regrets.exe | grep -A2 -B2 "Black Alpaca"
```

**Resultado**:
```
[----- Black Alpaca ---- ]
Password:
     ALP{%s}
```

### 8.2 Flag Final

El formato es `ALP{...}`, por lo tanto:

```
ALP{D0N7_T0UCH_MY_W00L_BR0}
```

---

## 9. Verificación

### 9.1 Resumen del Algoritmo

1. **Construcción**: El programa construye un array de 356 caracteres usando XOR con clave `0xF3A75869DEADBEEF`

2. **Índices**: Define 22 índices especiales en `v381` que apuntan a posiciones específicas

3. **Extracción**: Itera de j=0 a j=353, buscando valores que cumplan `valor + 2 = 356 - j`

4. **Orden**: Los 22 valores en `v381` se encuentran en orden de j creciente

5. **Reversión**: La string extraída se invierte al final

6. **Formato**: Se imprime con el formato `ALP{...}`

### 9.2 Diagrama del Flujo

```
[356 funciones] → [XOR] → [Array de 356 chars]
                                    ↓
                          [Índices en v381]
                                    ↓
                          [Algoritmo j-loop]
                                    ↓
                          [22 caracteres]
                                    ↓
                          [Reversión]
                                    ↓
                    D0N7_T0UCH_MY_W00L_BR0
                                    ↓
                          [Formato ALP{...}]
                                    ↓
                ALP{D0N7_T0UCH_MY_W00L_BR0}
```

---

## 10. Herramientas y Scripts Creados

### Scripts Python

1. **extract_xor.py**: Extrae el mapeo de funciones a valores XOR
2. **solve_complete.py**: Construye el array completo y extrae la flag
3. **func_map.json**: Almacena el mapeo de funciones a caracteres
4. **all_funcs.txt**: Lista ordenada de las 356 llamadas a funciones

### Comandos Bash Útiles

```bash
# Contar funciones
wc -l all_funcs.txt

# Buscar strings
strings regrets.exe | grep -i alpaca

# Buscar patrones en código
grep -E "sub_14000[A-F0-9]{4}" docu2.txt

# Extraer funciones en orden
grep -E "int32_t var_[0-9a-f]+ = sub_14000[a-f0-9]+\(\)" doc1.txt | \
  grep -oE "sub_14000[a-f0-9]+"
```

---

### Flag Final
```
ALP{D0N7_T0UCH_MY_W00L_BR0}
```



**Autor**: p0mb3r0
**Fecha**: 2025
**CTF**: AlpacaCTF - Black Alpaca Challenge
**Categoría**: Reversing

🦙 **"Don't touch my wool, bro!"** 🦙