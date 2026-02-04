# Writeup: My Gift - "Be smart"

**CTF:** Malwarespace 2025
**Categoria:** Reversing
**Flag:** `sm4rt_c0ntr4ct_x0r_xm45@malwarespace.com`

---

## Reconocimiento Inicial

Al recibir el archivo `my_gift.bin`, lo primero fue identificar de que tipo de archivo se trataba:

```bash
$ file my_gift.bin
my_gift.bin: data

$ xxd my_gift.bin | tail -5
00001b50: 5260 245f fd5b 9291 5050 565b 634e 487b  R`$_.[..PPV[cNH{
00001b60: 7160 e01b 5f52 6032 6004 5260 245f fdfe  q`.._R`2`.R`$_..
00001b70: a264 6970 6673 5822 1220 c385 4e1f 83ee  .dipfsX". ..N...
00001b80: f22d 992f 5d0b 54f8 0d4c fc3f 5442 5c8a  .-./].T..L.?TB\.
00001b90: 0c7d 51a4 795c 4bcf 97d6 6473 6f6c 6343  .}Q.y\K...dsolcC
00001ba0: 0008 1400 33                             ....3
```

Las cadenas `dipfsX`, `dsolcC` y `0008 1400 33` al final del archivo revelaron que se trataba de un **Smart Contract de Ethereum/Solidity** compilado con solc version 0.8.20.

El nombre del reto "Be smart" era una pista directa: **smart contract**.

---

## Analisis del Bytecode EVM

### Estructura del Contrato

El bytecode EVM tiene dos partes principales:
1. **Constructor** (codigo de despliegue)
2. **Runtime** (codigo ejecutable del contrato)

Separados por el marcador `5f395ff3fe`.

### Extraccion de Strings

```bash
$ strings my_gift.bin | grep -i need
Need 32 gifts
```

Esto indicaba que el contrato esperaba 32 "regalos" para revelar la flag.

---

## Analisis del Constructor

El constructor almacena 40 valores de 256 bits en slots de storage especificos:

```python
# Slots utilizados en el constructor:
[0, 46, 47, 65, 74, 83, 97, 117, 143, 146, 158, 167, 177, 185, 186, 187,
 200, 225, 237, 251, 259, 264, 284, 287, 288, 309, 325, 342, 356, 364,
 370, 381, 383, 398, 406, 408, 419, 431, 456, 485]
```

Cada slot almacena un hash de 256 bits que corresponde a `keccak256(key || mapping_slot)`.

---

## Analisis del Runtime

El runtime contiene la funcion `getFlag()` (selector `0xfd02ffb7`) que:

1. Verifica que se hayan enviado 32 "gifts"
2. Calcula cada byte de la flag usando valores del storage

### Patron de Calculo

Para cada byte de la flag, el codigo hace:

```
7f HASH 54          ; PUSH32 hash, SLOAD (carga valor del storage)
60 MOD 90 611558    ; PUSH1 mod_value, SWAP, PUSH2 0x1558 (funcion SUB)
5b 60 XOR 18        ; JUMPDEST, PUSH1 xor_value, XOR
```

La funcion en `0x1558` realiza una resta con verificacion de underflow (SafeMath).

---

## Descubrimiento Clave

El punto crucial fue descubrir que:

1. Los **valores PUSH32** en el constructor son los mismos **hashes** usados en el runtime para lookup
2. Los **numeros de slot** del constructor son los valores que se necesitan para el calculo
3. La formula es: `flag_char = ((slot_number - mod) & 0xFF) ^ xor`

### Relacion Hash -> Slot

```python
# El constructor almacena: storage[slot] = hash_value
# El runtime busca: storage[hash_value] pero usa slot_number para calcular

hash_to_slot = {
    "12f11d7a24fd4754...": 83,   # 's'
    "24d30d6da666a400...": 117,  # 'm'
    # ... etc
}
```

---

## Script de Solucion

```python
from Crypto.Hash import keccak
import re

def keccak256(data):
    k = keccak.new(digest_bits=256)
    k.update(data)
    return k.hexdigest()

# Leer bytecode
bytecode = open('bytecode.hex').read().strip()
runtime_marker = '5f395ff3fe'
constructor_end = bytecode.find(runtime_marker)
constructor = bytecode[:constructor_end]
runtime = bytecode[constructor_end + len(runtime_marker):]

# Parsear constructor para obtener slot -> valor
slot_to_value = {}
value_to_slot = {}
# ... (parsing del bytecode)

# Extraer patrones del runtime
for match in re.finditer(r'7f([0-9a-f]{64})54', runtime):
    hash_val = match.group(1)
    # Extraer mod y xor values
    # ...

    slot = value_to_slot.get(hash_val)
    if slot:
        result = ((slot - mod_val) & 0xFF) ^ xor_val
        flag_char = chr(result)
```

---

## Calculo de la Flag

| Pos | Slot | Mod | XOR | Calculo | Char |
|-----|------|-----|-----|---------|------|
| 0 | 83 | 60 | 100 | (83-60)^100 = 23^100 | 's' |
| 1 | 117 | 61 | 85 | (117-61)^85 = 56^85 | 'm' |
| 2 | 364 | 255 | 89 | (109)^89 | '4' |
| 3 | 309 | 119 | 204 | (190)^204 | 'r' |
| 4 | 158 | 94 | 52 | (64)^52 | 't' |
| 5 | 46 | 35 | 84 | (11)^84 | '_' |
| 6 | 65 | 52 | 110 | (13)^110 | 'c' |
| 7 | 186 | 95 | 107 | (91)^107 | '0' |
| 8 | 187 | 127 | 82 | (60)^82 | 'n' |
| 9 | 383 | 153 | 146 | (230)^146 | 't' |
| ... | ... | ... | ... | ... | ... |

---

## Flag Final

```
sm4rt_c0ntr4ct_x0r_xm45@malwarespace.com
```

---

## Lecciones Aprendidas

1. **Identificacion de formato**: Los bytes finales de un binario pueden revelar su tipo (metadata de Solidity)
2. **Smart Contracts**: El bytecode EVM tiene patrones reconocibles (PUSH, SLOAD, SSTORE, etc.)
3. **Ingenieria inversa de EVM**: Los valores almacenados en el constructor pueden ser claves para resolver el puzzle
4. **Keccak256**: Solidity usa keccak256 para calcular slots de mappings

---

## Herramientas Utilizadas

- `xxd` - Dump hexadecimal
- `strings` - Extraccion de strings
- Python con `pycryptodome` - Para keccak256
- Analisis manual de bytecode EVM

---

*Writeup by: CTF Player*
*Fecha: 2025*
