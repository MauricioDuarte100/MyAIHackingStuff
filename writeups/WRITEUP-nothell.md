# Hell CTF - Writeup Completo

## Información del Reto
- **Nombre**: Hell
- **Categoría**: Reversing
- **Archivo**: `hell.exe` (PE32+ executable, x86-64)
- **Dificultad**: Media-Alta

---

## Parte 1: Análisis Inicial

### Reconocimiento del Binario
Al ejecutar `hell.exe`, el programa muestra:
```
[ ~~~ Malware Space ~~~ ]
@@@ escape from hell @@@

password:
```

Solicita una contraseña. Si se ingresa algo incorrecto, muestra `[!] wrong input.` y termina.

### Análisis Estático con Decompilador
Usando los archivos decompilados (`deco1.txt`, `deco2.txt`), identifiqué los siguientes componentes clave:

1. **Función `main`**: Lee la entrada del usuario y la copia a un buffer global (`byte_14003C2A0`) de 66 bytes.

2. **Vectored Exception Handler (VEH)**: El binario registra un manejador de excepciones llamado `Handler` usando `AddVectoredExceptionHandler`.

3. **Función Despachadora (`sub_14004100E`)**: Ubicada en la sección `MYRWX`, esta función orquesta 66 verificaciones individuales.

### El Mecanismo de Ofuscación
El binario usa un esquema ingenioso:
- Ejecuta instrucciones privilegiadas (`hlt`, `cli`, etc.) que provocan excepciones `STATUS_PRIVILEGED_INSTRUCTION` (0xC0000096).
- El VEH captura estas excepciones y lee el registro `RAX`, que contiene un puntero a una función de verificación.
- Si la función retorna `true`, continúa; si retorna `false`, termina con "wrong input".

---

## Parte 2: Primera Flag Encontrada (Incorrecta)

### Desarrollo del Solver
Escribí un script en Python (`solve_hell.py`) que:

1. **Extrae los parámetros de cada check**: Dirección de función, clave XOR, longitud del código cifrado, y valor esperado.

2. **Desencripta el código automodificable**: Cada función de verificación tiene código cifrado con XOR que se desencripta en tiempo de ejecución.

3. **Emula las operaciones aritméticas**: El código desencriptado realiza operaciones (`add`, `sub`, `xor`, `rol`, `ror`) sobre el carácter de entrada.

4. **Fuerza bruta por carácter**: Para cada posición, prueba todos los caracteres ASCII printables (32-126) hasta encontrar uno cuyo resultado coincida con el valor esperado.

### Resultado Inicial
El solver produjo la siguiente "contraseña":
```
:II:Uo8re1nb^hveriO16b51H3Wr4lI9p<8:4IPtolK`u_9bk3]rH4[F7X5xxKOnMB
```

### Verificación con el Binario
```
password: :II:Uo8re1nb^hveriO16b51H3Wr4lI9p<8:4IPtolK`u_9bk3]rH4[F7X5xxKOnMB
[!] The flag was checked successfully!
```

**¡El binario la aceptó!** Parecía que habíamos terminado...

---

## Parte 3: El Problema - No Era la Flag Real

### La Pista del Organizador
Al enviar la flag al sistema de CTF, recibí feedback del organizador:
> "Uy, estás muy cerca. No es la flag, pero estás muy cerca. Ya casi lo tienes. **Revisa bien lo que hay dentro**. Los pasos que hiciste."

### Reflexión
La contraseña técnicamente funcionaba, pero la frase "revisa lo que hay dentro" y "los pasos que hiciste" me hizo pensar:
- ¿Hay información oculta en el proceso de verificación mismo?
- ¿Los datos extraídos durante el análisis contienen un mensaje?

---

## Parte 4: Descubrimiento de la Flag Real

### Hipótesis
Si la flag no es el input que satisface los checks, quizás está **codificada en los parámetros de los checks mismos**.

### Análisis de Metadatos
Modifiqué el solver para imprimir todos los valores intermedios:

```python
# Valores "target" = ExpectedValue / 84231
all_targets = []
for i in range(66):
    # ... extracción ...
    target_y = expected_val // 84231
    all_targets.append(target_y)

# Convertir a ASCII
print("".join([chr(t) if 32 <= t < 127 else '.' for t in all_targets]))
```

### El Resultado
```
Target Values (ASCII): 4n_am4z1ng_w4y_to_make_u_lose_t1m3_hehehehehe_and_the_flag_is_here
```

**¡Ahí estaba la flag real!**

### Explicación Técnica
Cada check tiene un "valor esperado" que es `target_y * 84231`. Estos valores `target_y` (52, 110, 95, ...) son los códigos ASCII de los caracteres de la flag real.

La estructura del reto era:
1. **Capa visible**: Encontrar un input que pase los checks (la contraseña técnica).
2. **Capa oculta**: Los valores de comparación forman un mensaje legible (la flag real).

---

## Parte 5: Flag Final

### Contraseña Técnica (Acepta el binario pero NO es la flag)
```
:II:Uo8re1nb^hveriO16b51H3Wr4lI9p<8:4IPtolK`u_9bk3]rH4[F7X5xxKOnMB
```

### Flag Real (Mensaje oculto en los checks)
```
4n_am4z1ng_w4y_to_make_u_lose_t1m3_hehehehehe_and_the_flag_is_here
```

### Flag Final para Enviar
Según las instrucciones del CTF ("agregar @malwarespace.com"):
```
4n_am4z1ng_w4y_to_make_u_lose_t1m3_hehehehehe_and_the_flag_is_here@malwarespace.com
```

---

## Lecciones Aprendidas

1. **No asumir que el primer resultado es el final**: Aunque el binario aceptó la contraseña, la flag estaba en otro lugar.

2. **Analizar los metadatos del proceso**: Los valores constantes usados en las verificaciones pueden contener información oculta.

3. **Prestar atención a las pistas**: "Revisa lo que hay dentro" indicaba mirar los datos internos del algoritmo, no solo el resultado.

---

## Archivos
- `hell.exe` - Binario del reto
- `solve_hell.py` - Script solver en Python
- `deco1.txt`, `deco2.txt` - Código decompilado
