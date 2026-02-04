# CTF Writeup: doom - Malwarespace 2025

## Challenge Info
- **Nombre:** doom
- **Categoría:** Reversing
- **Descripción:** *A strange holiday-themed executable was found in Santa's old archives. The elves say it used to be something much simpler before Santa packed it into this bulky form. Whatever it's hiding, it must be important.*

## Flag
```
schn0rr_w0rks_l1ke_a_ch4rm@malwarespace.com
```

---

## Análisis Inicial

El archivo `doom` es un ejecutable ELF de 64 bits:

```bash
$ file doom
doom: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, stripped
```

Al ejecutar `binwalk`, descubrimos que contiene un **archivo ZIP embebido** al final del binario con múltiples archivos Perl:

```bash
$ binwalk doom | grep -i zip
5294327       0x50C8F7        Zip archive data...
5819536       0x58CC90        End of Zip archive
```

Esto indica que el ejecutable fue empaquetado con **PAR (Perl Archive Packer)**.

---

## Extracción del Código Perl

Extraemos el contenido del ZIP embebido:

```bash
$ unzip -d extracted doom
```

Los archivos principales extraídos son:
- `script/main.pl` - Loader del PAR
- `script/doooooom.pl` - El script principal con la lógica del reto

---

## Análisis del Script: doooooom.pl

El script implementa un **Proof of Work basado en firmas Schnorr**:

```perl
my $json = do { local $/; <DATA> };
my $p = decode_json($json);

my $P   = Math::BigInt->from_hex($p->{P});
my $G   = Math::BigInt->from_hex($p->{G});
my $R   = Math::BigInt->from_hex($p->{R});
my $S   = Math::BigInt->from_hex($p->{s});
my $MOD = Math::BigInt->from_hex($p->{p});

# Verificación del password
my $hash = sha256_hex($password);
my $e = Math::BigInt->from_hex("0x$hash")->bmod($MOD);

my $lhs = modsub(mm($S, $G), $R);  # (s*G - R) mod p
my $rhs = mm($e, $P);               # (sha256(password)*P) mod p

if ($lhs == $rhs) {
    # Password correcto -> descifrar flag con RC4
}
```

### Parámetros del reto (en sección `__DATA__`):

```json
{
  "p": "0x100000000000000061",
  "G": "0x1337",
  "P": "0x1cd7d6aea7256755f",
  "R": "0xcf002281ba12a4328",
  "s": "0x47d9c9b06eecf9a9d",
  "chars": "sauzsc4ntr0h$",
  "note": "find the password such that (s*G - R) mod p == (sha256(password)*P) mod p",
  "meta": {
    "encrypted_flag": "ff38caaeba8002bb64cdcecc50083e80b1f9a1caf16a0cae513d",
    "nonce": "bae72cec0790b0b9"
  }
}
```

---

## Solución

### Paso 1: Calcular el valor objetivo de `e`

La ecuación a resolver es:
```
(s*G - R) mod p == (sha256(password) * P) mod p
```

Despejando `e = sha256(password) mod p`:
```
e = (s*G - R) * P^(-1) mod p
```

### Paso 2: Brute-force del password

Con el charset `sauzsc4ntr0h$` (12 caracteres únicos), realizamos brute-force:

```python
import hashlib
import itertools

p = 0x100000000000000061
P = 0x1cd7d6aea7256755f
G = 0x1337
R = 0xcf002281ba12a4328
s = 0x47d9c9b06eecf9a9d

lhs = (s * G - R) % p
target_e = (lhs * pow(P, -1, p)) % p

unique_chars = list(set('sauzsc4ntr0h$'))

for length in range(1, 12):
    for combo in itertools.product(unique_chars, repeat=length):
        password = ''.join(combo)
        hash_hex = hashlib.sha256(password.encode()).hexdigest()
        e = int(hash_hex, 16) % p
        if e == target_e:
            print(f'Found: {password}')
            exit(0)
```

**Password encontrado:** `schn0rr$` (juego de palabras con "Schnorr")

### Paso 3: Descifrar la flag con RC4

```python
import hashlib

password = 'schn0rr$'
nonce = bytes.fromhex('bae72cec0790b0b9')
encrypted_flag = bytes.fromhex('ff38caaeba8002bb64cdcecc50083e80b1f9a1caf16a0cae513d')

key_hash = hashlib.sha256(password.encode()).digest()
rc4_key = key_hash + nonce

# RC4 decrypt
decrypted = rc4(rc4_key, encrypted_flag)
print(decrypted.decode())  # schn0rr_w0rks_l1ke_a_ch4rm
```

---

## Conclusión

El reto combina:
1. **Análisis de binarios empaquetados** (PAR Packer)
2. **Criptografía** (esquema de firmas Schnorr)
3. **Brute-force** con charset limitado
4. **Descifrado RC4**

El nombre del password "schn0rr$" es un guiño directo al algoritmo de **Schnorr signatures** utilizado en el reto.

**Flag:** `schn0rr_w0rks_l1ke_a_ch4rm@malwarespace.com`
