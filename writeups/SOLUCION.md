# Solución - Reto de Reversing CTF

## Información del Reto
- **Tipo:** Reversing
- **Dificultad:** Warm-up
- **Flag encontrada:** `ALP{w4mup-r3v3rs1ng!!}`

---

## Proceso de Resolución

### 1. Análisis Inicial
Al examinar el directorio, encontré 10 archivos de código decompilado (`datos1.txt` a `datos10.txt`), resultado del análisis estático del binario original.

```bash
ls -la
```

**Archivos encontrados:**
- datos1.txt (82 KB)
- datos2.txt (46 KB)
- datos3.txt (109 KB)
- datos4.txt (24 KB)
- datos5.txt (194 KB)
- datos6.txt (89 KB)
- datos7.txt (45 KB)
- datos8.txt (45 KB)
- datos9.txt (72 KB)
- datos10.txt (132 KB)

### 2. Búsqueda de Patrones

Realicé búsquedas de patrones comunes en CTFs de reversing:

**Búsqueda de palabras clave:**
```bash
grep -rni "ALP\|flag\|FLAG" .
```

**Búsqueda de strings hexadecimales sospechosos:**
```bash
grep -rn "414c50\|4c6f6f6b" .
```

### 3. Análisis del Código

Al examinar `datos2.txt`, encontré la función principal del ransomware (`sub_404988`). El código muestra:

1. **Anti-debugging checks:** Múltiples llamadas a `IsDebuggerPresent()`
2. **Función de encriptación:** `sub_40116b()` que procesa archivos
3. **Strings ofuscados en hexadecimal**

### 4. Strings Hexadecimales Encontrados

En el código decompilado encontré dos strings hexadecimales importantes:

#### String 1 (línea 991 de datos2.txt):
```c
__builtin_strncpy(&var_3c3, ".4c6f6f6b20636c6f73657221", 0x1b);
```

#### String 2 (línea 1030 de datos2.txt):
```c
__builtin_strncpy(&var_3f3,
    ".SECRET_REDACTED_BY_ANTIGRAVITY217d", 0x2f);
```

### 5. Conversión Hexadecimal a ASCII

**String 1:** `.4c6f6f6b20636c6f73657221`

Removiendo el punto inicial y convirtiendo:
```bash
echo "4c6f6f6b20636c6f73657221" | xxd -r -p
```
**Resultado:** `Look closer!`

**String 2:** `.SECRET_REDACTED_BY_ANTIGRAVITY217d`

Removiendo el punto inicial y convirtiendo:
```bash
echo "SECRET_REDACTED_BY_ANTIGRAVITY217d" | xxd -r -p
```
**Resultado:** `ALP{w4mup-r3v3rs1ng!!}`

### 6. Verificación de la Flag

La flag sigue el formato estándar de CTF:
- Prefijo: `ALP{` (identificador del CTF)
- Contenido: `w4mup-r3v3rs1ng!!` (warm-up reversing)
- Sufijo: `}`

---

## Contexto del Código

### Lógica del Ransomware (Simulado)

El binario simula un ransomware que:

1. **Lee archivos del sistema** con una extensión específica
2. **Aplica encriptación** usando la función `sub_40116b()`
3. **Escribe un mensaje al final** del archivo encriptado

El mensaje escrito depende de una condición:

```c
if (data_40800c > 0x1337 && !memcmp(_Buf1, &data_407250, 1))
{
    // Escribe la FLAG
    _Str = ".SECRET_REDACTED_BY_ANTIGRAVITY217d";
}
else
{
    // Escribe el mensaje de pista
    _Str = ".4c6f6f6b20636c6f73657221";
}
```

### Anti-debugging

El código contiene múltiples chequeos anti-debugging:

```c
if (IsDebuggerPresent())
{
    sub_4061ef();
    sub_401000();  // Loop infinito
    /* no return */
}
```

Esto hace que el análisis dinámico (debugging) sea más difícil, forzando el uso de análisis estático.

---

## Herramientas Utilizadas

1. **grep** - Búsqueda de patrones en archivos
2. **xxd** - Conversión de hexadecimal a ASCII
3. **Análisis manual** del código decompilado

---

## Conclusión

La flag se encontró mediante **análisis estático** del código decompilado, identificando strings hexadecimales ofuscados que contenían el formato típico de una flag CTF. El mensaje "Look closer!" servía como pista para seguir buscando.

**Flag:** `ALP{w4mup-r3v3rs1ng!!}`

**Significado:** Warm-up Reversing (reto de calentamiento de ingeniería inversa)
