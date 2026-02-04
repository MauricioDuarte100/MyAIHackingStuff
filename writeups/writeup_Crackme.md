# Crackme - Writeup

## Información del reto
- **Categoría:** Reversing (Beginner)
- **Archivo:** `crackme` (ELF 64-bit)

## Análisis

### 1. Reconocimiento inicial

```bash
$ file crackme
crackme: ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped
```

### 2. Extracción de strings

```bash
$ strings crackme
```

Strings relevantes encontradas:
- `Enter your username:`
- `admin`
- `Enter your password:`
- `Congrats! Your password is correct. Use this password as flag`
- Funciones de OpenSSL: `EVP_sha256`, `EVP_DigestInit_ex`, etc.

### 3. Análisis del binario

El programa:
1. Pide un **username** (debe ser `admin`)
2. Pide un **password**
3. Calcula el **SHA256** del password
4. Lo compara con un hash hardcodeado

### 4. Extracción del hash esperado

Usando `objdump -s -j .rodata crackme` se extrajo el hash SHA256 esperado:

```
fcf730b6d95236ecd3c9fc2d92d7b6b2bb061514961aec041d6c7a7192f592e4
```

### 5. Cracking del hash

El hash corresponde a un password común que se puede encontrar en bases de datos online o mediante diccionario:

```bash
$ echo -n "secret123" | sha256sum
fcf730b6d95236ecd3c9fc2d92d7b6b2bb061514961aec041d6c7a7192f592e4
```

### 6. Verificación

```bash
$ echo -e "admin\nsecret123" | ./crackme
Enter your username: Enter your password: Congrats!
Your password is correct. Use this password as flag
```

## Flag

```
secret123
```
