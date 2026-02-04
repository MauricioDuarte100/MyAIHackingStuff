# Sanity Check - MalwareSpace CTF 2025

## Descripcion del reto

**Categoria:** Reversing
**Dificultad:** Facil
**Mensaje:** "Just checking if you are worthy to do this CTF"

Se nos proporciona un binario ELF llamado `main`.

---

## Analisis inicial

### Identificacion del archivo

```bash
$ file main
main: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, not stripped
```

El binario no esta stripped, lo que significa que conserva los simbolos de depuracion.

### Extraccion de strings

```bash
$ strings main
...
[ ~~~~ Just checking if you are worthy ~~~~ ]
Enter seed:
%d
flag:
...
_ZL4flag
_ZL3len
_Z9operationc
...
```

Encontramos:
- Mensajes de texto que el programa imprime
- Simbolos importantes: `flag`, `len`, y una funcion `operation`

---

## Analisis estatico

### Funcion main

Desensamblando con `objdump -d main`:

```asm
000000000000123c <main>:
    ; ... setup del stack frame ...

    ; Imprime "[ ~~~~ Just checking if you are worthy ~~~~ ]"
    1261:   call   1100 <puts@plt>

    ; Imprime "Enter seed: "
    1275:   call   10b0 <printf@plt>

    ; Lee el seed con scanf("%d", &seed)
    1290:   call   1110 <__isoc23_scanf@plt>

    ; Operacion de modulo: seed % 8602863
    1295:   mov    -0x10(%rbp),%eax
    129b:   imul   $0x3e67f485,%rdx,%rdx
    ...
    12b0:   imul   $0x8344ef,%edx,%ecx    ; 0x8344ef = 8602863
    12b6:   sub    %ecx,%eax

    ; srand(seed % 8602863)
    12be:   call   10d0 <srand@plt>

    ; Imprime "flag: "
    12d2:   call   10b0 <printf@plt>

    ; Loop: para cada byte de flag encriptada
    12e0:   mov    -0xc(%rbp),%eax        ; i
    12e5:   lea    0xd34(%rip),%rdx       ; _ZL4flag
    12ec:   movzbl (%rax,%rdx,1),%eax     ; flag[i]
    12f5:   call   1209 <_Z9operationc>   ; operation(flag[i])
    12fc:   call   10f0 <putchar@plt>     ; imprimir resultado

    ; Compara i con len (54)
    1305:   cmp    0xd4a(%rip),%eax       ; _ZL3len
    130b:   jl     12e0                   ; continuar si i < len
```

### Funcion operation

```asm
0000000000001209 <_Z9operationc>:
    ; Guarda el caracter de entrada
    1217:   mov    %al,-0x14(%rbp)

    ; Llama a rand()
    121a:   call   10c0 <rand@plt>

    ; Calcula rand() % 256 (obtiene byte bajo)
    1221:   mov    %eax,%edx
    1223:   sar    $0x1f,%eax
    1226:   shr    $0x18,%eax
    1229:   add    %eax,%edx
    122b:   movzbl %dl,%edx
    122e:   sub    %eax,%edx

    ; XOR con el caracter de entrada
    1233:   movsbl -0x14(%rbp),%eax
    1237:   xor    -0x4(%rbp),%eax

    123b:   ret
```

**Pseudocodigo:**
```c
char operation(char c) {
    return c ^ (rand() % 256);
}
```

### Datos en .rodata

```bash
$ objdump -s -j .rodata main
```

| Direccion | Contenido |
|-----------|-----------|
| 0x2020 | Flag encriptada (54 bytes) |
| 0x2058 | Longitud: 0x36 (54) |

Flag encriptada (hex):
```
63 62 34 26 c5 49 bd f3 ed d3 c2 cc 1d c4 a4 64
2c de 50 24 a8 b5 85 7b 5a ed 9d 63 aa cd 06 bc
be 07 4a 10 ff 73 6b 4c f7 bb 97 b9 f7 d7 9c ae
52 32 3c d0 4d 56 7b
```

---

## Entendiendo el algoritmo

El programa hace lo siguiente:

1. Lee un **seed** del usuario
2. Calcula `seed % 8602863`
3. Inicializa el PRNG con `srand(seed_mod)`
4. Para cada byte de la flag encriptada:
   - Genera un numero aleatorio con `rand()`
   - XOR el byte con `rand() % 256`
   - Imprime el resultado

**Diagrama del cifrado:**
```
seed_input --> mod 8602863 --> srand() --> rand() --> XOR --> output
                                             ^          ^
                                             |          |
                                        (% 256)    encrypted_byte
```

---

## Solucion

Como el espacio de busqueda esta limitado por el modulo (8,602,863 posibles seeds), podemos hacer fuerza bruta buscando el seed que produzca texto ASCII imprimible.

### Script de solucion

```python
import ctypes

# Usar la misma implementacion de rand() que el binario
libc = ctypes.CDLL("libc.so.6")

# Flag encriptada extraida del binario
encrypted_flag = bytes([
    0x63, 0x62, 0x34, 0x26, 0xc5, 0x49, 0xbd, 0xf3,
    0xed, 0xd3, 0xc2, 0xcc, 0x1d, 0xc4, 0xa4, 0x64,
    0x2c, 0xde, 0x50, 0x24, 0xa8, 0xb5, 0x85, 0x7b,
    0x5a, 0xed, 0x9d, 0x63, 0xaa, 0xcd, 0x06, 0xbc,
    0xbe, 0x07, 0x4a, 0x10, 0xff, 0x73, 0x6b, 0x4c,
    0xf7, 0xbb, 0x97, 0xb9, 0xf7, 0xd7, 0x9c, 0xae,
    0x52, 0x32, 0x3c, 0xd0, 0x4d, 0x56, 0x7b
])

MODULO = 8602863

def decrypt(seed):
    libc.srand(seed % MODULO)
    result = []
    for byte in encrypted_flag:
        rand_val = libc.rand() % 256
        result.append(byte ^ rand_val)
    return bytes(result)

# Fuerza bruta
for seed in range(MODULO):
    decrypted = decrypt(seed)
    try:
        text = decrypted.decode('ascii')
        if all(32 <= ord(c) <= 126 for c in text):
            print(f"Seed: {seed}")
            print(f"Flag: {text}")
            break
    except:
        pass
```

### Ejecucion

```
$ python3 solve.py
Seed: 778921
Flag: th1s_fl4g_is_just_2_check_u_are_worthy@malwarespace.com
```
C:\Users\Ariel\Documents\charla>main.exe
password: th1s_1s_th3_passw0rd_u_r_l00k1ng_f0r@malwarespace.com
[+] You got the flag.. but where is it??!
---

## Flag

```
th1s_fl4g_is_just_2_check_u_are_worthy@malwarespace.com
```

**Seed correcto:** `778921`

---

## Conclusiones

- El reto utiliza cifrado XOR con PRNG seeded
- La debilidad esta en el espacio de claves limitado (modulo 8,602,863)
- No fue necesario ejecutar el binario, solo analisis estatico
- Herramientas utilizadas: `file`, `strings`, `objdump`, `nm`, Python con ctypes

---

*Writeup por: Antigravity Code*
*CTF: MalwareSpace 2025*
