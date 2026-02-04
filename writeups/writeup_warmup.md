# Malware Space X-MAS CTF 2025 - Warmup (Reversing)

## Descripcion del reto

El reto consiste en una pagina web con un juego tipo Wordle donde debemos adivinar una palabra de 32 letras en 6 intentos.

## Archivos proporcionados

- `index.html` - Interfaz del juego
- `app.js` - Logica del juego en JavaScript

## Analisis

### 1. Identificacion de la palabra objetivo

Al revisar `app.js`, encontramos que la palabra objetivo esta almacenada como un array de hashes:

```javascript
const WORD = [102949, 86905, 101612, 116319, 86905, 109634, 92253, 110971,
              106960, 86905, 89579, 92253, 89579, 96264, 109634, 97601,
              110971, 112308, 102949, 86905, 110971, 110971, 104286, 105623,
              116319, 93590, 101612, 86905, 100275, 92253, 110971, 117656];
```

### 2. Funcion de hash

La funcion `simple_hash()` calcula un hash para cada letra:

```javascript
function simple_hash(str) {
    let hash = 0;
    let nonce = 1337;
    for (let i = 0; i < str.length; i++) {
        hash = (hash << 6) - hash + str.charCodeAt(i);
        hash = hash & hash;
    }
    return hash * nonce;
}
```

Esta funcion:
1. Itera sobre cada caracter del string
2. Aplica una operacion de desplazamiento de bits y suma el codigo ASCII
3. Multiplica el resultado final por 1337 (nonce)

### 3. Reversing del hash

Como el juego solo acepta letras A-Z y cada posicion es una sola letra, podemos crear una tabla de lookup calculando el hash de cada letra:

```javascript
const hashToLetter = {};
for (let c = 65; c <= 90; c++) {
    const letter = String.fromCharCode(c);
    hashToLetter[simple_hash(letter)] = letter;
}
```

Aplicando esto al array `WORD`:

```javascript
const word = WORD.map(h => hashToLetter[h]).join('');
// Resultado: MALWARESPACECHRISTMASSNOWFLAKESX
```

### 4. Obtencion de la flag

Al acertar la palabra, el codigo ejecuta un XOR entre la palabra y un array de bytes para revelar la flag:

```javascript
let bytes = [0x3a,0x72,0x20,0x34,0x71,0x3f,0x76,0x0c,0x62,0x1e,0x2e,0x71,
             0x2f,0x3f,0x66,0x3b,0x60,0x0b,0x3e,0x31,0x67,0x30,0x7d,0x10,
             0x2f,0x2b,0x2d,0x32,0x14,0x26,0x27,0x3e];
let xor = [];
for (let i = 0; i < bytes.length; i++) {
    xor.push(bytes[i] ^ guess.charCodeAt(i));
}
```

## Solucion

Script completo para obtener la flag:

```javascript
function simple_hash(str) {
    let hash = 0;
    let nonce = 1337;
    for (let i = 0; i < str.length; i++) {
        hash = (hash << 6) - hash + str.charCodeAt(i);
        hash = hash & hash;
    }
    return hash * nonce;
}

// Crear mapa inverso hash -> letra
const hashToLetter = {};
for (let c = 65; c <= 90; c++) {
    const letter = String.fromCharCode(c);
    hashToLetter[simple_hash(letter)] = letter;
}

// Array de hashes de la palabra objetivo
const WORD = [102949, 86905, 101612, 116319, 86905, 109634, 92253, 110971,
              106960, 86905, 89579, 92253, 89579, 96264, 109634, 97601,
              110971, 112308, 102949, 86905, 110971, 110971, 104286, 105623,
              116319, 93590, 101612, 86905, 100275, 92253, 110971, 117656];

// Decodificar la palabra
const word = WORD.map(h => hashToLetter[h]).join('');
console.log('Palabra:', word);

// Calcular la flag con XOR
let bytes = [0x3a,0x72,0x20,0x34,0x71,0x3f,0x76,0x0c,0x62,0x1e,0x2e,0x71,
             0x2f,0x3f,0x66,0x3b,0x60,0x0b,0x3e,0x31,0x67,0x30,0x7d,0x10,
             0x2f,0x2b,0x2d,0x32,0x14,0x26,0x27,0x3e];
let flag = bytes.map((b, i) => String.fromCharCode(b ^ word.charCodeAt(i))).join('');
console.log('Flag:', flag + '@malwarespace.com');
```

## Flag

```
w3lc0m3_2_m4lw4r3_sp4c3_xmas_ctf@malwarespace.com
```
