# Domain CTF Challenge - Solución Completa

## 🚩 Flag Final
```
ALP{anssan.www.legitdownloadcnet.ru}
```

---

## 📋 Información del Desafío

**Nombre**: Domain  
**Categoría**: Reverse Engineering  
**Archivo**: `domain` (ARM 32-bit ELF)  
**Objetivo**: Obtener la URL del C&C para el 3 de Marzo de 2016

---

## 🔍 Análisis del Binario

### Información Técnica
```bash
$ file domain
domain: ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), dynamically linked, stripped
```

### Strings Relevantes
```bash
$ strings domain
monday
tuesday
wednesday
thursday
friday
saturday
sunday
malwareday
Today's host: %s.www.legitdownloadcnet.ru\n
```

**Conclusión inicial**: El binario implementa un **Domain Generation Algorithm (DGA)** de malware.

---

## 🧩 Algoritmo DGA Identificado

### 1. Cálculo del Valor de Fecha

```c
int calculate_date_value() {
    time_t t = time(0);
    struct tm *tm = gmtime(&t);
    
    return tm_yday + ((tm_year + tm_yday) << 8);
}
```

**Fórmula**: `date_value = tm_yday + ((tm_year + tm_yday) << 8)`

- `tm_year`: Años desde 1900
- `tm_yday`: Día del año (0-365 en C)

### 2. Array de Días

```c
char *days[8] = {
    "monday",      // 0
    "tuesday",     // 1
    "wednesday",   // 2
    "thursday",    // 3
    "friday",      // 4
    "saturday",    // 5
    "sunday",      // 6
    "malwareday"   // 7
};
```

### 3. Generación del Subdominio

```c
char* generate_subdomain(int date_value) {
    char *result = calloc(1, 6);
    char concat[24] = {0};
    
    // Seleccionar dos días usando los primeros 2 bytes
    int idx1 = ((char*)&date_value)[0] & 7;
    int idx2 = ((char*)&date_value)[1] & 7;
    
    strcat(concat, days[idx1]);
    strcat(concat, days[idx2]);
    int len = strlen(concat);
    
    // Generar 6 caracteres en orden inverso
    for (int i = 0; i < 6; i++) {
        int byte_idx = i & 3;
        int char_idx = ((char*)&date_value)[byte_idx] % len;
        result[5 - i] = concat[char_idx];
    }
    
    return result;
}
```

---

## 💻 Implementación en Python

```python
#!/usr/bin/env python3
import struct
from datetime import datetime

days = [
    "monday", "tuesday", "wednesday", "thursday",
    "friday", "saturday", "sunday", "malwareday"
]

def calculate_date_value(year, month, day):
    d = datetime(year, month, day)
    tt = d.timetuple()
    
    tm_year = year - 1900
    tm_yday = tt.tm_yday - 1  # Python usa 1-366, C usa 0-365
    
    value = tm_yday + ((tm_year + tm_yday) << 8)
    return value & 0xFFFF

def generate_subdomain(date_value):
    value_bytes = struct.pack('<I', date_value)
    
    idx1 = value_bytes[0] & 7
    idx2 = value_bytes[1] & 7
    
    concat = days[idx1] + days[idx2]
    L = len(concat)
    
    result = [''] * 6
    for i in range(6):
        byte_idx = i & 3
        byte_val = value_bytes[byte_idx]
        char_idx = byte_val % L
        result[5 - i] = concat[char_idx]
    
    return ''.join(result)

# Fecha objetivo: 3 de Marzo 2016
year, month, day = 2016, 3, 3
date_value = calculate_date_value(year, month, day)
subdomain = generate_subdomain(date_value)

print(f"Date Value: 0x{date_value:04x}")
print(f"Subdomain: {subdomain}")
print(f"C&C URL: {subdomain}.www.legitdownloadcnet.ru")
print(f"Flag: ALP{{{subdomain}.www.legitdownloadcnet.ru}}")
```

---

## 🎯 Solución Paso a Paso

### Fecha Objetivo: 3 de Marzo 2016

#### 1. Cálculo del `tm_yday`
```
2016 es año bisiesto:
- Enero: 31 días
- Febrero: 29 días (bisiesto)
- Marzo 1-2: 2 días
- Total: 31 + 29 + 2 = 62 días
```

#### 2. Cálculo del `date_value`
```
tm_year = 2016 - 1900 = 116
tm_yday = 62 (0-indexed)

date_value = tm_yday + ((tm_year + tm_yday) << 8)
           = 62 + ((116 + 62) << 8)
           = 62 + (178 << 8)
           = 62 + 45568
           = 45630
           = 0xB23E
```

#### 3. Bytes en Little Endian
```
0xB23E = [0x3E, 0xB2, 0x00, 0x00]
```

#### 4. Selección de Días
```
idx1 = 0x3E & 7 = 6 → "sunday"
idx2 = 0xB2 & 7 = 2 → "wednesday"

concat = "sundaywednesday" (length = 15)
```

#### 5. Generación de Caracteres
```
i=0: byte[0]=0x3E, (62 % 15) = 2  → 'n', pos[5] = 'n'
i=1: byte[1]=0xB2, (178 % 15) = 13 → 's', pos[4] = 's'
i=2: byte[2]=0x00, (0 % 15) = 0   → 's', pos[3] = 's'
i=3: byte[3]=0x00, (0 % 15) = 0   → 's', pos[2] = 's'
i=4: byte[0]=0x3E, (62 % 15) = 2  → 'n', pos[1] = 'n'
i=5: byte[1]=0xB2, (178 % 15) = 13 → 'a', pos[0] = 'a'
```

**Resultado**: `anssan`

#### 6. URL del C&C
```
anssan.www.legitdownloadcnet.ru
```

---

## ✅ Verificación

```bash
$ python3 solve_specific.py
Date: 2016-3-3
tm_year: 116
tm_yday: 62
Calculated Value: 0xb23e
Subdomain: anssan
Flag: ALP{anssan.www.legitdownloadcnet.ru}
```

---

## 🔑 Flag

```
ALP{anssan.www.legitdownloadcnet.ru}
```

---

## 📚 Lecciones Aprendidas

1. **Análisis de múltiples decompiladores**: Usar IDA, Ghidra, Reko, etc. para obtener mejor comprensión
2. **Años bisiestos**: Crucial para cálculos de fecha (2016 → Feb tiene 29 días)
3. **Little Endian**: Arquitectura ARM usa little endian
4. **Flag completa**: No solo el subdominio, sino la URL completa del C&C
5. **String "malwareday"**: Pista sobre la naturaleza del desafío (DGA de malware)

---

## 🛠️ Herramientas Utilizadas

- `file`, `strings`, `readelf`, `objdump` - Análisis estático
- IDA Pro, Ghidra, Reko - Decompiladores
- Python 3 - Implementación y verificación
- Análisis manual - Ingeniería inversa del algoritmo
