# Writeup: Ruidos en la Red - CTF ESET 2025

## Descripción del Reto

> Recibís un paquete de capturas de red que, en apariencia, muestran actividad cotidiana. Sin embargo, entre conexiones dispersas, solicitudes fuera de horario y patrones que no terminan de encajar, algo llama la atención. Entre los metadatos y los nombres utilizados en ciertos intercambios aparece una referencia peculiar: nicole. Puede parecer anecdótica, pero en este desafío cada detalle puede marcar la diferencia.

**Archivo proporcionado:** `CTF- III.pcapng`

---

## Análisis

### Paso 1: Reconocimiento inicial del archivo PCAP

Primero obtuve las estadísticas del protocolo para entender qué tipo de tráfico contenía la captura:

```bash
tshark -r "CTF- III.pcapng" -q -z io,phs
```

**Resultado:**
```
Protocol Hierarchy Statistics
Filter:

eth                                      frames:756 bytes:166992
  ip                                     frames:750 bytes:166562
    udp                                  frames:737 bytes:165548
      rdpudp                             frames:731 bytes:164072
      data                               frames:6 bytes:1476
    tcp                                  frames:13 bytes:1014
      tls                                frames:6 bytes:588
  llc                                    frames:4 bytes:240
```

El tráfico es principalmente **RDPUDP** (Remote Desktop Protocol sobre UDP) entre dos hosts, con algunos paquetes de datos adicionales.

### Paso 2: Extracción de strings

Busqué cadenas de texto legibles en el archivo PCAP:

```bash
strings "CTF- III.pcapng" | head -20
```

**Resultado clave encontrado:**
```
64-bit Windows 10 (1909), build 18363
Wireshark
\Device\NPF_{B0100E20-014A-4532-A703-0DA5D18391C5}
Ethernet0
Ping test 1
GET / HTTP/1.1
Host: ctf.local
User-Agent: student
FLAG=3s3T_PUE2o25_N3tw0rk
```

### Paso 3: Verificación del hallazgo

Para confirmar, extraje los campos de datos de los paquetes:

```bash
tshark -r "CTF- III.pcapng" -Y "data" -T fields -e data
```

El segundo paquete contenía datos en hexadecimal que decodifiqué:

```bash
echo "SECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITY6b0d0a" | xxd -r -p
```

**Resultado:**
```
GET / HTTP/1.1
Host: ctf.local
User-Agent: student

FLAG=3s3T_PUE2o25_N3tw0rk
```

### Paso 4: Análisis del hexdump

También verifiqué directamente en el archivo con hexdump:

```bash
hexdump -C "CTF- III.pcapng" | grep -A2 "FLAG"
```

```
000001e0  6e 74 0d 0a 0d 0a 46 4c  41 47 3d 33 73 33 54 5f  |nt....FLAG=3s3T_|
000001f0  50 55 45 32 6f 32 35 5f  4e 33 74 77 30 72 6b 0d  |PUE2o25_N3tw0rk.|
```

---

## Estructura del tráfico

- **IPs involucradas:** 192.168.1.104 ↔ 192.168.1.117
- **Protocolo principal:** RDPUDP (puerto 3389)
- **Paquetes totales:** 756
- **Sistema capturador:** Windows 10 (1909) con Wireshark

La flag estaba oculta en un paquete de datos que simulaba una petición HTTP hacia `ctf.local`.

---

## Flag

```
3s3T_PUE2o25_N3tw0rk
```

### Interpretación (leetspeak):

La flag decodificada representa: **ESET_PUE2025_Network**

- `3s3T` → ESET
- `PUE2o25` → PUE2025
- `N3tw0rk` → Network

---

## Herramientas utilizadas

- `tshark` - Análisis de paquetes por línea de comandos
- `strings` - Extracción de cadenas legibles
- `xxd` - Conversión hexadecimal
- `hexdump` - Visualización del contenido binario

---

## Lecciones aprendidas

1. Siempre revisar los strings de un archivo PCAP como primer paso rápido
2. Los paquetes marcados como "data" pueden contener información oculta
3. El tráfico aparentemente normal (RDP) puede ser una distracción mientras la flag está en paquetes menores
