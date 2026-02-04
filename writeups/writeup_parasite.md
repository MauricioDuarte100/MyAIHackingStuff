# Writeup: Parasite (Crypto - Beginner)

## Descripción del Desafío

Se nos proporciona un archivo `mtp.txt` con 10 líneas de datos en hexadecimal.

## Análisis Inicial

El nombre del archivo `mtp.txt` es una pista clave: **MTP = Many Time Pad**.

El One-Time Pad (OTP) es teóricamente irrompible, pero **solo si la clave se usa una única vez**. Cuando la misma clave se reutiliza para cifrar múltiples mensajes (Many Time Pad), el cifrado se vuelve vulnerable.

### Vulnerabilidad del Many Time Pad

Si tenemos dos ciphertexts cifrados con la misma clave:
```
C1 = P1 ⊕ K
C2 = P2 ⊕ K
```

Al hacer XOR entre ellos:
```
C1 ⊕ C2 = (P1 ⊕ K) ⊕ (P2 ⊕ K) = P1 ⊕ P2
```

La clave se cancela y obtenemos el XOR de los plaintexts, lo cual permite técnicas como **crib dragging**.

## Proceso de Resolución

### Paso 1: Convertir los ciphertexts

```python
ciphertexts_hex = [
    "0c21397010190a28141b042d1d5658000030480a35141d5f2201550011041c31410a0d5a08305e50271b411c05120353",
    "750023700b1b0431140d186c081a5f474e0d0710735f035c344f02060d4d5901040f0d461726411c0012044c0a120313",
    # ... (10 líneas en total)
]
ciphertexts = [bytes.fromhex(c) for c in ciphertexts_hex]
```

### Paso 2: Análisis de frecuencia inicial

Usé análisis de frecuencia para recuperar una clave aproximada. La técnica consiste en probar cada byte posible (0-255) para cada posición y seleccionar el que produce más caracteres ASCII imprimibles.

```python
def recover_key():
    key = bytearray(min_len)
    for pos in range(min_len):
        best_score = -1
        best_key = 0
        for k in range(256):
            score = 0
            for ct in ciphertexts:
                decrypted = ct[pos] ^ k
                if 32 <= decrypted < 127:
                    score += 1
            if score > best_score:
                best_score = score
                best_key = k
        key[pos] = best_key
    return bytes(key)
```

### Paso 3: Identificar el contexto

La clave parcial recuperada mostró:
```
UNLP{we_4llLiv3inTheS4m3CouitryCakl3rCapRtalo
```

Esto reveló:
1. El formato de flag es `UNLP{...}`
2. El mensaje parece ser leetspeak relacionado con "capitalism"
3. El nombre del reto "Parasite" sugiere conexión con la película

### Paso 4: Crib Dragging con plaintexts conocidos

Busqué citas famosas de la película **Parasite** (2019) de Bong Joon-ho. El discurso sobre "no tener plan" es icónico:

> "You know what kind of plan never fails? No plan..."

### Paso 5: Recuperar la clave completa

Usando el plaintext conocido para la primera línea:
```python
pt1 = "You know what kind of plan never fails? No plan."
ct1 = ciphertexts[0]

key = bytearray(len(ct1))
for i in range(len(pt1)):
    key[i] = ct1[i] ^ ord(pt1[i])
```

## Solución Final

```python
#!/usr/bin/env python3

ciphertexts_hex = [
    "0c21397010190a28141b042d1d5658000030480a35141d5f2201550011041c31410a0d5a08305e50271b411c05120353",
    "750023700b1b0431140d186c081a5f474e0d0710735f035c344f02060d4d5901040f0d461726411c0012044c0a120313",
    "3a3a6c321e571533550202290d581325013b0345324602462d0b55171b075763250508131d2c14501d1c080202531915",
    "303d29700b120a2f58094c21081256490f741809325a4d472c4f06021117096308024c470c264103191b13181a53051c",
    "39226c2712030d7f4d0319734934461d4e3c0d1736141a56630e070b541c16344d4c1f5f012611190713411806140809",
    "3d2b3e701419452b5c094c2a05195c1b40743b0a7f14195b261d10490752172c410209560063071f1b54004c191f0c13",
    "7b6e153f0e57063e5a4b186c0e19131e1c3b0602734304472b4f1b01540215220f1f421333264114061a4618491d0818",
    "316e383f5b1a0434514c0d6c191a52074e3207177355034a37071c00135c590a154c085c01300f571d540c0d1d07080f",
    "753924310f57123658004c240806430c007406002b40431306191000541b1f6315040913072c141e1d06184c0e16190e",
    "752a29230f050a2651084c231b5640060230480a264041132d001701100b5920001e09404a63261f1d54081856",
]

ciphertexts = [bytes.fromhex(c) for c in ciphertexts_hex]

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

# Plaintext conocido (cita de Parasite)
pt1 = "You know what kind of plan never fails? No plan."
ct1 = ciphertexts[0]

# Recuperar clave
key = bytes(ct1[i] ^ ord(pt1[i]) for i in range(len(pt1)))

print("FLAG:", key.decode())
```

## Mensajes Descifrados

Los 10 ciphertexts forman un monólogo continuo de la película:

| # | Mensaje |
|---|---------|
| 1 | You know what kind of plan never fails? No plan. |
| 2 | No plan at all. You know why? Because life cann |
| 3 | ot be planned. Look around you. Did you think th |
| 4 | ese people made a plan to sleep in the sports ha |
| 5 | ll with you? But here we are now, sleeping toget |
| 6 | her on the floor. So, there's no need for a plan |
| 7 | . You can't go wrong with no plans. We don't nee |
| 8 | d to make a plan for anything. It doesn't matter |
| 9 | what will happen next. Even if the country gets |
| 10 | destroyed or sold out, nobody cares. Got it? |

## Flag

```
UNLP{we_4llLiv3inTheS4m3CountryCall3dCapitalism}
```

**Decodificado:** "We all live in the same country called Capitalism"

Esta flag hace referencia directa al tema central de la película Parasite: la crítica al capitalismo y la desigualdad social.

## Lecciones Aprendidas

1. **Nunca reutilizar claves en OTP** - El One-Time Pad solo es seguro si la clave se usa una única vez
2. **El contexto importa** - El nombre del reto ("Parasite") fue clave para identificar los plaintexts
3. **Crib dragging** - Conocer parte del plaintext permite recuperar la clave completa
