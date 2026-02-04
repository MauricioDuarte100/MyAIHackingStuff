# Solución del Challenge: Creepy PDF Resume

## Análisis Técnico

### 1. Extracción de Caracteres Unicode Tag

Los caracteres Unicode Tag (U+E0000 a U+E007F) están ocultos en los campos de metadatos del PDF:

- **UserComment**: Contiene la primera parte del mensaje
- **Copyright**: Contiene la segunda parte del mensaje

### 2. Mensaje Extraído (Raw)

```
TUQTVQSUk<__[O0O]#m45146135k9OS_e\TOU^Z_iOQO`YjjQObYWXdO^_gm
```

Longitud: 60 caracteres

### 3. Decodificación de Bytes

Cada secuencia de 4 bytes UTF-8 `F3 A0 XX YY` representa un carácter Unicode Tag que codifica un carácter ASCII.

#### UserComment (19 caracteres):
```
T U Q T V Q S U k < _ _ [ O 0 O ] # m
```

#### Copyright (41 caracteres):
```
4 5 1 4 6 1 3 5 k 9 O S _ e \ T O U ^ Z _ i O Q O ` Y j j Q O b Y W X d O ^ _ g m
```

## Opciones de Flag

### Opción 1: Mensaje Original (sin conversión)
```
deadface{TUQTVQSUk<__[O0O]#m45146135k9OS_e\TOU^Z_iOQO`YjjQObYWXdO^_gm}
```

### Opción 2: Con Dígitos Convertidos
Conversión: cada dígito + 32 = carácter ASCII
- 4 → $ (36)
- 5 → % (37)
- 1 → ! (33)
- etc.

```
deadface{TUQTVQSUk<__[O O]#m$%!$&!#%k)OS_e\TOU^Z_iOQO`YjjQObYWXdO^_gm}
```
(Nota: el `0` en `[O0O]` se convierte en espacio)

### Opción 3: Mensaje en Minúsculas
```
deadface{tuqtvqsuk<__[o0o]#m45146135k9os_e\tou^z_ioqo`yjjqobyxdo^_gm}
```

## Herramientas Utilizadas

1. `exiftool -U lambiresume.pdf` - Extracción de metadatos con Unicode
2. Script Python personalizado para decodificar bytes UTF-8 a caracteres ASCII
3. Análisis hexadecimal de secuencias de bytes

## Scripts de Decodificación

Ver:
- `manual_decode.py` - Decodificador principal
- `decode_tags.py` - Decodificador alternativo
- `final_decode.py` - Análisis final

## Notas

El PDF contiene metadata sospechosa que sugiere que es parte del challenge DEADFACE:
- Software: "DeadFace Suite 3.9"
- Artist: "Mr. Lambert the Assassin"
- Make: "Ethereal Devices Inc."
