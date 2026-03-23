# Writeup: Citizen Four - MetaRed CTF

## Información del Desafío
**Archivo:** `challenge.pcapng`
**Objetivo:** Encontrar la flag oculta en la captura de tráfico de red.

## 1. Análisis Inicial
Al analizar el archivo `challenge.pcapng`, identificamos tráfico TCP/IP. Específicamente, se observan conexiones SSL/TLS (TLSv1) entre un cliente (`172.18.0.1`) y tres servidores distintos:
- `172.18.0.2`
- `172.18.0.3`
- `172.18.0.4`

Cada servidor presenta un certificado X.509 autofirmado con la organización `CERTUNLP`. Dado que el tráfico está cifrado con TLS, no podemos leer el contenido directamente (que parece ser HTTP sobre TLS).

## 2. Extracción de Certificados
Utilizando `tshark`, extrajimos los certificados presentados en los mensajes `Server Hello` de cada handshake TLS.

```bash
# Comando para extraer los certificados en formato hexadecimal
tshark -r challenge.pcapng -Y "tls.handshake.type == 11" -T fields -e tls.handshake.certificate > certs_hex.txt
```

Luego convertimos estos volcados hexadecimales a archivos binarios DER y extrajimos sus Claves Póblicas RSA, específicamente los Módulos ($N$). 

## 3. Análisis de Vulnerabilidad (RSA Common Factor Attack)
En implementaciones RSA inseguras (a menudo debido a una baja entropía durante la generación de claves), es posible que dos claves distintas compartan un factor primo $p$. Si esto ocurre, la seguridad de ambas claves se rompe completamente.

Para verificar esto, calculamos el **Máximo Comón Divisor (GCD)** entre los módulos de los tres certificados:

$$ 
\text{GCD}(N_1, N_2) = 1
$$ 
$$ 
\text{GCD}(N_2, N_3) = 1
$$ 
$$ 
\text{GCD}(N_1, N_3) = p \quad (\text{Donde } p > 1)
$$ 

**Hallazgo:** Los certificados del servidor 1 (`172.18.0.2`) y del servidor 3 (`172.18.0.4`) compartían un factor primo comón.

## 4. Explotación y Recuperación de Claves Privadas
Con el factor comón $p$ conocido, podemos factorizar ambos módulos trivialmente:

Para la Clave 1: $q_1 = N_1 / p$
Para la Clave 3: $q_3 = N_3 / p$

Con los primos $p$ y $q$ recuperados, podemos calcular el exponente privado $d$ y reconstruir las claves privadas completas (formato PEM). Usamos el siguiente script en Python:

```python
from math import gcd
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# Funciones auxiliares para leer binarios y modinv...

# 1. Cargar Módulos
n1 = get_modulus_int("modulus_1.bin") # De 172.18.0.2
n3 = get_modulus_int("modulus_3.bin") # De 172.18.0.4
e = 65537

# 2. Calcular Factor Comón
p = gcd(n1, n3)

# 3. Calcular los otros factores
q1 = n1 // p
q3 = n3 // p

# 4. Calcular Claves Privadas
phi1 = (p - 1) * (q1 - 1)
d1 = modinv(e, phi1)

phi3 = (p - 1) * (q3 - 1)
d3 = modinv(e, phi3)

# 5. Guardar como PEM (key1.pem, key3.pem)
# ... (código de generación de PEM)
```

## 5. Desencriptación del Tráfico
Con las claves privadas recuperadas (`key1.pem` y `key3.pem`), utilizamos Wireshark/Tshark para descifrar el tráfico SSL y ver las peticiones HTTP en texto plano.

Comando utilizado:
```bash
tshark -r challenge.pcapng \
  -o "tls.keys_list:172.18.0.2,443,http,key1.pem;172.18.0.4,443,http,key3.pem" \
  -Y "http" -V
```

## 6. Resultado
Al inspeccionar la respuesta HTTP desencriptada (HTTP 200 OK) proveniente de `172.18.0.2` o `172.18.0.4`, encontramos la flag en el cuerpo de la respuesta:

**Flag:**
```
UNLP{Assume-SECRET_REDACTED_BY_ANTIGRAVITYesPer5econd}
```
