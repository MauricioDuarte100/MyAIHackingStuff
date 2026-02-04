# No Signal TV - ESET CTF 2025

## Descripción del Reto

Se nos proporciona una imagen PNG llamada `no-signal-tv.png` que muestra barras de colores similares a una señal de TV sin transmisión. En el centro de la imagen se puede leer un mensaje sutil: **"What you (don't) see?"**

## Análisis Inicial

### Información de la Imagen

```
File Name: no-signal-tv.png
Image Size: 4400x2475
Color Type: Palette (8-bit indexed)
```

### Metadatos Sospechosos

Al analizar los metadatos con `exiftool`, encontramos varios campos en Base64:

| Campo | Valor Base64 | Decodificado |
|-------|--------------|--------------|
| Artist | `IyMjIyMjIyMjIyBURVhUICMjIyMjIyMjIyM=` | `########## TEXT ##########` |
| Copyright | `QEBAQEBAQEBAIHh4eHh4eCBAQEBAQEBAQEA=` | `@@@@@@@@@@ xxxxxx @@@@@@@@@@` |
| Subject | `JSUlJSUlJSUlJSBkZWMuICUlJSUlJSUlJSU=` | `%%%%%%%%%% dec. %%%%%%%%%%` |
| Author | `IyMjIyMjIyMjIyB4eHh4eHggIyMjIyMjIyMjIw=` | `########## xxxxxx ##########` |
| Device | `IyMjIyMjIyMjIyBnb2luZyAjIyMjIyMjIyMj` | `########## going ##########` |

Los metadatos nos dan una pista: **"TEXT dec. going"** - indicando que debemos buscar texto en valores decimales.

### Advertencia Clave

ExifTool también reportó:
```
Warning: [minor] Trailer data after PNG IEND chunk
```

Esto indica datos adicionales después del chunk final de la imagen.

## La Clave: La Paleta de Colores

La imagen usa un **Color Type: Palette**, lo que significa que los colores están indexados en una paleta embebida. Al extraer y analizar la paleta, notamos algo peculiar:

**Cada color tiene solo un canal activo (R, G o B)**, mientras los otros dos son 0.

```python
colors = [
    (51, 0, 0),    # Solo R = 51  → '3'
    (0, 115, 0),   # Solo G = 115 → 's'
    (0, 0, 51),    # Solo B = 51  → '3'
    (84, 0, 0),    # Solo R = 84  → 'T'
    (0, 95, 0),    # Solo G = 95  → '_'
    (0, 0, 80),    # Solo B = 80  → 'P'
    # ... y así sucesivamente
]
```

## Solución

El valor del canal activo de cada color corresponde a un código ASCII. Extrayendo el valor no-cero de cada entrada de la paleta y convirtiéndolo a carácter:

```python
# Lista de colores de la paleta (RGB)
colors = [
    (51, 0, 0), (0, 115, 0), (0, 0, 51), (84, 0, 0), (0, 95, 0),
    (0, 0, 80), (85, 0, 0), (0, 69, 0), (0, 0, 50), (48, 0, 0),
    (0, 50, 0), (0, 0, 53), (95, 0, 0), (0, 66, 0), (0, 0, 76),
    (49, 0, 0), (0, 110, 0), (0, 0, 100), (35, 0, 0), (0, 33, 0),
    (0, 0, 124), (92, 0, 0), (0, 47, 0), (0, 0, 124), (64, 0, 0),
    (0, 103, 0), (0, 0, 51)
]

def active_channel_value(rgb):
    r, g, b = rgb
    if r != 0: return r
    elif g != 0: return g
    elif b != 0: return b
    return 0

# Convertir a ASCII
flag = ''.join([chr(active_channel_value(c)) for c in colors])
print(flag)
```

## Flag

```
3s3T_PUE2025_BL1nd#!|\/|@g3
```

La flag hace referencia a "Blind Image" (imagen ciega) - un guiño a la técnica de esteganografía utilizada donde la información está "oculta a plena vista" en la paleta de colores.

## Herramientas Utilizadas

- `exiftool` - Análisis de metadatos
- `binwalk` - Detección de datos embebidos
- Python/PIL - Extracción y análisis de la paleta de colores

## Lecciones Aprendidas

1. Las imágenes con paleta indexada pueden ocultar datos en los propios valores de la paleta
2. Los metadatos de imagen pueden contener pistas codificadas en Base64
3. El mensaje "What you (don't) see?" era literal: la flag estaba en lo que no vemos directamente (los valores RGB de la paleta)
