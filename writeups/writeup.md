# Writeup: Ultra-Pensador-3000

## Descripcion del Reto

**Nombre:** Ultra-Pensador-3000
**Categoria:** Binary Exploitation / Pwn
**Pista:** "Si encontrar la falencia puedes, aparecer la bandera debe"

## Archivos Proporcionados

- `Ultra-Pensador-3000` - Binario ELF de 64 bits
- `deco1.txt` a `deco4.txt` - Codigo decompilado del binario

## Analisis Inicial

### Reconocimiento del Binario

```bash
file Ultra-Pensador-3000
# ELF 64-bit LSB executable, x86-64
```

### Revision del Codigo Decompilado

Al analizar el codigo en `deco3.txt`, se identifica la funcion `main()`:

```c
undefined8 main(void)
{
  char *pcVar1;
  char local_d8 [208];

  puts("SECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITY010010010110101011010010");
  print_banner();
  puts("SECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITY010101011110101011010010");
  puts("");
  puts("");
  printf("Ingresa tu nombre:\n> ");
  pcVar1 = fgets(local_d8, 200, stdin);
  if (pcVar1 != (char *)0x0) {
    puts("");
    sleep(2);
    puts("Pensando...");
    sleep(2);
    puts("Procesando...");
    sleep(2);
    puts("Consultando fuentes...");
    sleep(3);
    puts("");
    puts("Tu nombre es: ");
    printf(local_d8);    // <-- VULNERABILIDAD AQUI
    sleep(1);
    puts("");
    puts("Gracias por utilizar el Ultra-Pensador-3000.");
    puts("");
  }
  return 0;
}
```

## La Falencia: Format String Vulnerability

### Identificacion

En la linea 186 del codigo decompilado se encuentra:

```c
printf(local_d8);
```

El input del usuario (`local_d8`) se pasa **directamente** como primer argumento de `printf()`, sin un especificador de formato.

### Codigo Vulnerable vs Codigo Seguro

```c
// VULNERABLE - El usuario controla el formato
printf(local_d8);

// SEGURO - Formato fijo, usuario solo proporciona datos
printf("%s", local_d8);
```

### Impacto de la Vulnerabilidad

Un atacante puede usar especificadores de formato para:

| Especificador | Accion |
|---------------|--------|
| `%p` | Leer direcciones de memoria del stack |
| `%x` | Leer valores hexadecimales del stack |
| `%s` | Leer strings desde direcciones en el stack |
| `%n` | **Escribir** en memoria (cantidad de bytes impresos) |

## Explotacion

### Prueba de Concepto

```bash
echo '%p.%p.%p.%p.%p.%p' | ./Ultra-Pensador-3000
```

**Output:**
```
Tu nombre es:
0x72626d6f6e207554.(nil).(nil).0x2d1f42dd.(nil).0x70252e70252e7025...
```

Esto confirma que podemos leer valores del stack.

### Busqueda de la Flag

Al buscar strings en el binario:

```bash
strings Ultra-Pensador-3000 | grep -iE "(flag|eset|ctf)"
```

**Output:**
```
flag_var
```

Esto indica que existe una variable llamada `flag_var`. Buscamos mas:

```bash
strings Ultra-Pensador-3000
```

**Output relevante:**
```
3s3T_PUE2025_th3_Cl4nKer_!
```

### Confirmacion con Analisis del Binario

```bash
objdump -t ./Ultra-Pensador-3000 | grep -i flag
```

**Output:**
```
0000000000400820 l     O .rodata    000000000000001b    flag_var
```

La flag esta almacenada en:
- **Direccion:** `0x400820`
- **Seccion:** `.rodata` (datos de solo lectura)
- **Tamano:** 27 bytes (0x1b)

### Verificacion Hexadecimal

```bash
xxd ./Ultra-Pensador-3000 | grep -A1 "3s3T"
```

**Output:**
```
00000820: 3373 3354 5f50 5545 3230 3235 5f74 6833  3s3T_PUE2025_th3
00000830: 5f43 6c34 6e4b 6572 5f21 0000 0000 0000  _Cl4nKer_!......
```

## Flag

```
3s3T_PUE2025_th3_Cl4nKer_!
```

O en formato estandar CTF:

```
ESET{3s3T_PUE2025_th3_Cl4nKer_!}
```

## Leccion Aprendida

**Nunca** pasar input del usuario directamente a funciones de formato como `printf()`, `sprintf()`, `fprintf()`, etc. Siempre usar un formato fijo:

```c
// Incorrecto
printf(user_input);

// Correcto
printf("%s", user_input);
```

## Herramientas Utilizadas

- `strings` - Extraccion de cadenas del binario
- `objdump` - Analisis de simbolos
- `xxd` - Visualizacion hexadecimal
- Codigo decompilado (Ghidra/RetDec/Binary Ninja)

## Referencias

- [OWASP - Format String Attack](https://owasp.org/www-community/attacks/Format_string_attack)
- [CWE-134: Use of Externally-Controlled Format String](https://cwe.mitre.org/data/definitions/134.html)
