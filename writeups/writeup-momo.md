# writeup-momo.md – Reversing (momo)

Este writeup explica **paso a paso** cómo llegué desde el binario `momo` hasta el string tipo “mail” invertido, y cómo se reconstruye la flag.

---

## 0) Fingerprinting del binario

Comandos:

```bash
file momo
sha256sum momo
```

Salida:

```text
/mnt/data/momo: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=072d43df16e10af4f3d79a4851e9b2175f2dbcfc, not stripped
241055e116c1a6966c09343d2439cd64013de0450a9ae644cfd3820b378123a1  /mnt/data/momo
```

Conclusiones rápidas:
- Es un **ELF x86_64 PIE** (Linux).
- **No está strippeado** → conserva símbolos (esto acelera mucho el reversing).
- Por los símbolos (`core::`, `alloc::`, `std::` y nombres largos), es un binario **Rust**.

---

## 1) Localizar la función interesante

Listé símbolos demangleados:

```bash
nm --demangle momo | grep -E "momo::(main|decoy)"
nm --demangle momo | grep -E "momo::.*Stage>::exec" | head
```

Aparecen:
- `momo::main`
- `momo::decoy`
- muchas funciones del tipo:

```
<momo::XXXXXXXXXXXXXXX as momo::Stage>::exec
```

Eso sugiere un diseño: **un pipeline de “stages”**, cada uno con un método `exec`.

---

## 2) Revisar `momo::main`: “la trampa”

Desensamblé `main`:

```bash
objdump -d --demangle momo | sed -n '/<momo::main>:/,/^$/p'
```

Se ve un patrón típico de challenge:
1) llama a `momo::decoy`
2) ejecuta `ud2` (instrucción inválida)

`ud2` produce un crash/trap si se ejecuta. Esto suele usarse para cortar el flujo “normal” y obligarte a mirar el código real.

**Conclusión:** la lógica útil vive en `momo::decoy`.

---

## 3) Encontrar el orden real de los “stages”

El punto clave es que **no necesito adivinar** el orden: `momo::decoy` contiene `call` explícitos a cada stage.

Comando para ver sólo esas llamadas:

```bash
objdump -d --demangle momo | sed -n '/<momo::decoy>:/,/^$/p' | grep -E 'call.*Stage>::exec'
```

En este binario hay **60** invocaciones a `Stage>::exec`.  
Ese es el **orden real** en el que el programa ejecuta los stages.

---

## 4) Entender qué hace un stage (patrón repetido)

Tomé un stage cualquiera y miré su `exec`. El patrón se repite en todos:

1. arma un “token” esperado (constante en heap/stack)
2. lo compara con algún input/estado (muchas veces con instrucciones SIMD como `pcmpeqb`)
3. si pasa la comparación, **emite un carácter** hacia la salida

El detalle clave: el carácter aparece como un inmediato ASCII escrito en el stack, por ejemplo:

- `movl $0x65, 0x14(%rsp)` → `0x65` = `'e'`
- `movl $0x3f, 0x14(%rsp)` → `0x3f` = `'?'`

Ejemplo real (stage que emite `?`):

```asm
   22eb6:	48 b8 48 4f 4c 4f 5f 	movabs $0x4b4f545f4f4c4f48,%rax
   22f61:	66 0f 74 d0          	pcmpeqb %xmm0,%xmm2
   22f6c:	66 0f 74 c1          	pcmpeqb %xmm1,%xmm0
   22f74:	66 0f d7 c0          	pmovmskb %xmm0,%eax
   22f7f:	c7 44 24 14 3f 00 00 	movl   $0x3f,0x14(%rsp)
   22fd3:	ff 15 af 83 04 00    	call   *0x483af(%rip)        # 6b388 <_DYNAMIC+0x288>
```

La línea importante ahí es:

- `movl   $0x3f,0x14(%rsp)` → `?`

Luego el stage prepara un pequeño “objeto” (punteros/len) y llama a la rutina que concatena ese byte al output. En este binario esa rutina aparece en el disassembly cerca de una referencia `6b388`.

---

## 5) Extraer automáticamente el carácter de cada stage

Como:
- el binario tiene símbolos,
- `decoy` contiene el orden de `Stage>::exec`,
- y cada `exec` escribe un inmediato ASCII antes de “emitir”,

podemos automatizar:

1) Desensamblar todo con `objdump -d --demangle`  
2) Sacar el orden de stages parseando las `call ... Stage>::exec` dentro de `momo::decoy`  
3) Para cada stage:
   - buscar la llamada de “emisión” (en este binario, la primera línea que contiene `6b388`)
   - mirar hacia atrás y capturar el `movl/movb $0xNN, ...(%rsp)` con ASCII printable

Así se recupera **1 carácter por stage**.

---

## 6) Resultado: flag y mail invertido

### 6.1 String reconstruido (orden normal)
```text
d0n_c4ngr3j0_?s_b@ck_and_br1ng_th3_fl@g!!!!@malwarespace.com
```

### 6.2 String invertido (reverse completo)
```text
moc.ecapserawlam@!!!!g@lf_3ht_gn1rb_dna_kc@b_s?_0j3rgn4c_n0d
```

> Ese segundo (`reverse`) es el “mail invertido”: exactamente el mismo contenido pero en orden inverso.

---

## 7) Script reproducible (extrae todo desde el binario)

Guardalo como `extract_flag.py`:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import subprocess
import sys

def run(cmd: str) -> str:
    return subprocess.check_output(["bash","-lc", cmd], text=True, errors="replace")

def extract_func_block(disas: str, name: str) -> str:
    hdr = re.escape(name + ">:")
    m = re.search(rf"{hdr}\n(.*?)(?:\n\n|$)", disas, re.S)
    return m.group(1) if m else ""

def extract_char_from_block(block: str):
    lines = block.splitlines()
    out_call_idx = None
    for i, l in enumerate(lines):
        if "6b388" in l:
            out_call_idx = i
            break

    def parse_imm(line: str):
        mm = re.search(r"movl\s+\$0x([0-9a-f]+),0x[0-9a-f]+\(%rsp\)", line)
        if mm:
            v = int(mm.group(1), 16)
            return v if 0x20 <= v <= 0x7e else None
        mm = re.search(r"movb\s+\$0x([0-9a-f]+),0x[0-9a-f]+\(%rsp\)", line)
        if mm:
            v = int(mm.group(1), 16)
            return v if 0x20 <= v <= 0x7e else None
        return None

    if out_call_idx is not None:
        for j in range(out_call_idx, max(-1, out_call_idx - 80), -1):
            v = parse_imm(lines[j])
            if v is not None:
                return v

    for l in lines:
        v = parse_imm(l)
        if v is not None:
            return v
    return None

def main():
    if len(sys.argv) != 2:
        print(f"Uso: {sys.argv[0]} ./momo", file=sys.stderr)
        sys.exit(1)

    binpath = sys.argv[1]
    disas = run(f"objdump -d --demangle {binpath}")

    m = re.search(r"<momo::decoy>:\n(.*?)(?:\n\n|$)", disas, re.S)
    if not m:
        raise RuntimeError("No pude encontrar momo::decoy")
    decoy = m.group(1)

    call_re = re.compile(r"call\s+[0-9a-fx]+\s+<(<momo::.*? as momo::Stage>::exec)>")
    stage_order = call_re.findall(decoy)
    if not stage_order:
        raise RuntimeError("No encontré calls a Stage>::exec en decoy")

    out = []
    for name in stage_order:
        block = extract_func_block(disas, name)
        v = extract_char_from_block(block)
        out.append(chr(v) if v is not None else "?")

    flag = "".join(out)
    print(flag)
    print(flag[::-1])

if __name__ == "__main__":
    main()
```

Ejecución:

```bash
python3 extract_flag.py ./momo
```

---

## 8) Flag final

La flag reconstruida (orden normal) es:

```text
d0n_c4ngr3j0_?s_b@ck_and_br1ng_th3_fl@g!!!!@malwarespace.com
```
