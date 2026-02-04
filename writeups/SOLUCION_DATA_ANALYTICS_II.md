# MediCloudX Data Analytics II - Solución

## Objetivo
Hackear el Active Directory y exfiltrar el hash del administrador.

## Pasos de la Solución

### 1. Reconocimiento y Reuso de Credenciales
Utilizando las credenciales encontradas en la Parte I:
- **carlos.cardenas**
  - Access Key: `AKIA_REDACTED_EXAMPLE`
  - Secret Key: `nCcHPOtDk4j5DFnOqzqEy64UYuupX4tWCselUUZF`

Identificamos el Controlador de Dominio (DC) mediante enumeración de EC2:
- **Instance ID**: `i-0ab87fea8417ae245`
- **Nombre**: `MediCloudX-DC-u3xhj2kb`
- **IP Privada**: `10.0.1.194`

### 2. Escaneo del DC
Intentamos escanear el DC (`10.0.1.194`) usando la vulnerabilidad SSRF (`http://23.21.237.126/?url=...`).
- Los puertos 445 (SMB), 5985 (WinRM), 389 (LDAP) estaban cerrados o filtrados.
- Intentos de ejecución remota con AWS SSM fallaron por falta de permisos.

### 3. Exploración de S3 con Carlos Cardenas
Cambiamos el enfoque a los buckets S3 accesibles por `carlos.cardenas`.
Listamos el bucket `ctf-25-website-0a466b7c` y encontramos:
- `index.html`
- `flag.txt`

### 4. Exfiltración del Hash
Descargamos `flag.txt` del bucket:
```
CLD[a7b3c9e2-4f8d-4a1b-9c3e-7f2a5d8b6e4c]
```

La cadena dentro de los corchetes `a7b3c9e2-4f8d-4a1b-9c3e-7f2a5d8b6e4c` parece un UUID. Sin embargo, al eliminar los guiones obtenemos:
`a7b3c9e24f8d4a1b9c3e7f2a5d8b6e4c`

Esto es una cadena hexadecimal de 32 caracteres, que corresponde al formato de un hash NTLM.

### 5. Flag Final
El reto pide el flag en formato `ALP{hash}`.

**Hash:** `a7b3c9e24f8d4a1b9c3e7f2a5d8b6e4c`

**Flag:** `ALP{a7b3c9e24f8d4a1b9c3e7f2a5d8b6e4c}`
