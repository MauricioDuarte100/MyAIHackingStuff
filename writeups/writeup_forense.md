# Mi Primer Captura - Writeup

**Categoría:** Forense
**Archivo:** capture1.pcap

## Descripción

Se nos proporciona un archivo de captura de red (pcap) para analizar.

## Análisis

### 1. Reconocimiento inicial

```bash
capinfos capture1.pcap
```

- 108 paquetes
- Duración: ~92 segundos
- Protocolos: TCP/HTTP

### 2. Jerarquía de protocolos

```bash
tshark -r capture1.pcap -q -z io,phs
```

Se identifica tráfico HTTP con datos de formularios (`urlencoded-form`).

### 3. Extracción de datos HTTP

```bash
tshark -r capture1.pcap -Y "http" -T fields -e urlencoded-form.key -e urlencoded-form.value
```

Se observan múltiples intentos de login al endpoint `/login`:

| Usuario | Contraseña |
|---------|------------|
| admin | supersecret123 |
| admin | supersecret |
| root | supersecret |
| root | root |
| root | **CYB{http_plaintext_credentials_found}** |

## Flag

```
CYB{http_plaintext_credentials_found}
```

## Lección

El reto demuestra el peligro de transmitir credenciales en texto plano sobre HTTP. Un atacante con acceso a la red puede capturar fácilmente usuarios y contraseñas sin cifrar.
