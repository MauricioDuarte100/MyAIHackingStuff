# Volume - Malware Space CTF 2025 Writeup

## Información del Reto

| Campo | Valor |
|-------|-------|
| **Nombre** | Volume |
| **Categoría** | Reversing |
| **Archivos** | `volume.exe`, `code.vm` |

**Enunciado:**
> A strange virtual machine built for Malware Space has surfaced. It runs custom bytecode, does weird stuff, and spits out mysterious output. Your job? Figure out what this quirky VM is really doing. It is more easy than you think!

---

## Análisis Inicial

### Archivos Proporcionados

```bash
$ ls -la
-rw-r--r-- 1 user user    365 Dec 11 00:00 code.vm
-rw-r--r-- 1 user user 309248 Dec 11 00:00 volume.exe
```

- `volume.exe`: Ejecutable de Windows (PE64) - La máquina virtual
- `code.vm`: Archivo binario de 365 bytes - El bytecode a ejecutar

### Inspección del Bytecode

```bash
$ xxd code.vm
00000000: 0201 8bf0 ffff 0202 3b2f 0000 0200 0c05  ........;/......
00000010: 0000 0f10 0200 b71d 0000 0f10 0200 c808  ................
...
00000160: 0000 0f10 02 00 0c05 0000 0f10 ff         .............
```

Observaciones inmediatas:
- Patrón repetitivo: `02 00 XX XX XX XX 0f 10`
- Termina con `ff` (probable HALT)
- Los primeros bytes parecen ser inicializaciones

---

## Ingeniería Inversa de la VM

### Análisis del Código Decompilado

Al analizar el código decompilado del `volume.exe`, encontré la función principal de ejecución de la VM con un switch statement que maneja los opcodes:

```c
switch (v28) {
    case 0x02:  // LOAD 32-bit value into register
        reg = next_byte();
        value = next_32bit_le();
        registers[reg] = value;
        break;
        
    case 0x0F:  // MODULAR EXPONENTIATION
        // Llama a sub_14000CB90(vm, reg0, reg1, reg2)
        reg[0] = modexp(reg[0], reg[1], reg[2]);
        break;
        
    case 0x10:  // PRINT CHARACTER
        putchar(reg[0]);
        break;
        
    case 0xFF:  // HALT
        return;
}
```

### Función Crítica: Exponenciación Modular

La función `sub_14000CB90` implementa **exponenciación modular rápida** (square-and-multiply):

```c
int64_t modexp(int64_t vm, uint32_t base, uint32_t exp, uint32_t mod) {
    uint32_t result = 1;
    base = base % mod;
    
    while (exp > 0) {
        if (exp & 1)
            result = (result * base) % mod;
        exp >>= 1;
        base = (base * base) % mod;
    }
    return result;
}
```

Esto calcula: `result = base^exp mod mod`

---

## Decodificación del Bytecode

### Estructura del Bytecode

```
Offset 0x00: 02 01 8b f0 ff ff    → reg[1] = 0xfffff08b (exponente)
Offset 0x06: 02 02 3b 2f 00 00    → reg[2] = 0x00002f3b = 12091 (módulo)

Para cada carácter:
    02 00 XX XX XX XX    → reg[0] = valor cifrado (32-bit LE)
    0f                   → reg[0] = pow(reg[0], reg[1], reg[2])
    10                   → putchar(reg[0])

Offset final: ff         → HALT
```

### Valores Extraídos

| Parámetro | Valor | Hexadecimal |
|-----------|-------|-------------|
| Exponente (reg1) | 4294963339 | 0xfffff08b |
| Módulo (reg2) | 12091 | 0x2f3b |

---

## Criptoanálisis RSA

### Factorización del Módulo

El módulo 12091 es un número pequeño, fácilmente factorizable:

```python
n = 12091
# 12091 = 107 × 113
p = 107
q = 113
```

### Cálculo de φ(n)

```python
phi = (p - 1) * (q - 1)
phi = 106 * 112
phi = 11872
```

### El Problema

El exponente `e = 0xfffff08b` del bytecode **no produce caracteres ASCII válidos** directamente. Esto indica que:

1. El bytecode fue generado con un exponente diferente
2. Necesitamos encontrar el exponente correcto que descifre los valores

### Fuerza Bruta del Exponente

Dado que φ(n) = 11872 es pequeño, podemos probar todos los exponentes posibles:

```python
data = open('code.vm', 'rb').read()
n = 12091

# Extraer valores cifrados
ciphers = []
offset = 12
while offset < len(data):
    if data[offset] == 0xff:
        break
    if data[offset:offset+2] == b'\x02\x00':
        c = int.from_bytes(data[offset+2:offset+6], 'little')
        ciphers.append(c)
        offset += 8
    else:
        offset += 1

# Probar todos los exponentes
for test_e in range(1, 11873):
    result = []
    valid = True
    for c in ciphers:
        m = pow(c, test_e, n)
        if 32 <= m < 127:
            result.append(chr(m))
        else:
            valid = False
            break
    if valid:
        print(f"e={test_e}: {''.join(result)}")
```

### Resultado

Solo **dos exponentes** producen caracteres ASCII válidos:
- `e = 1979`
- `e = 7915` (que es 1979 + 5936, un múltiplo de factores de φ)

---

## Flag

```
m4lw4r3_und3r_th3_xm4s_tr33@malwarespace.com
```

---

## Script de Solución Completo

```python
#!/usr/bin/env python3
"""
Volume - Malware Space CTF 2025
Solver Script
"""

def solve():
    data = open('code.vm', 'rb').read()
    
    # Parámetros RSA
    n = 12091          # = 107 * 113
    phi = 11872        # = 106 * 112
    
    # Extraer ciphertexts del bytecode
    ciphers = []
    offset = 12  # Después de las inicializaciones de registros
    
    while offset < len(data):
        if data[offset] == 0xff:  # HALT
            break
        if data[offset:offset+2] == b'\x02\x00':  # LOAD reg0
            cipher = int.from_bytes(data[offset+2:offset+6], 'little')
            ciphers.append(cipher)
            offset += 8  # 2 (opcode+reg) + 4 (value) + 2 (0f 10)
        else:
            offset += 1
    
    print(f"[*] Módulo n = {n} = 107 × 113")
    print(f"[*] φ(n) = {phi}")
    print(f"[*] Cantidad de caracteres cifrados: {len(ciphers)}")
    print(f"[*] Buscando exponente correcto...\n")
    
    # Fuerza bruta sobre todos los exponentes posibles
    for e in range(1, phi + 1):
        flag = ""
        valid = True
        
        for c in ciphers:
            m = pow(c, e, n)
            if 32 <= m < 127:
                flag += chr(m)
            else:
                valid = False
                break
        
        if valid:
            print(f"[+] Exponente encontrado: e = {e}")
            print(f"[+] FLAG: {flag}")
            return flag
    
    print("[-] No se encontró un exponente válido")
    return None

if __name__ == "__main__":
    solve()
```

---

## Lecciones Aprendidas

1. **VMs personalizadas**: Siempre buscar el switch principal que decodifica opcodes
2. **RSA débil**: Con módulos pequeños, factorización trivial permite recuperar φ(n)
3. **Fuerza bruta**: Cuando el espacio de búsqueda es pequeño (< 12000), es viable probar todos los valores
4. **"More easy than you think"**: La pista indicaba que no había trampa - solo entender la matemática básica

---

## Referencias

- [Exponenciación Modular](https://es.wikipedia.org/wiki/Exponenciaci%C3%B3n_modular)
- [RSA Cryptosystem](https://es.wikipedia.org/wiki/RSA)
- [Función de Euler φ(n)](https://es.wikipedia.org/wiki/Funci%C3%B3n_%CF%86_de_Euler)

---

**Autor:** Writeup generado durante el análisis del reto  
**Competencia:** Malware Space CTF 2025
