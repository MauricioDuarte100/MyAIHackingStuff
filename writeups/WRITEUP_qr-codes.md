# Writeup: QR Codes CTF Challenge

## Flag Encontrada
```
UNLP{DualQR_C0d3s_4r3_Aw3s0m3!}
```

## Descripción del Reto

El desafío presentaba un único archivo: `qr.png` con el mensaje:
> "This challenge can be very easy or very difficult — it all depends on your luck."
> "P.S. It is not a web challenge, don't search vulnerabilities there"

---

## Metodología de Resolución

### 1. Análisis Inicial

El primer paso fue intentar decodificar el QR code con herramientas estándar:

```bash
# Instalación del entorno virtual
python3 -m venv venv
source venv/bin/activate
pip install pillow pyzbar opencv-python qreader
```

Script básico de decodificación (`decode_qr.py`):
```python
from PIL import Image
from pyzbar import pyzbar
import cv2

# Intentar con pyzbar
img = Image.open("qr.png")
decoded = pyzbar.decode(img)

# Intentar con OpenCV
img_cv = cv2.imread("qr.png")
detector = cv2.QRCodeDetector()
data, bbox, _ = detector.detectAndDecode(img_cv)
```

**Resultado:** ❌ Ninguna herramienta estándar pudo decodificar el QR.

---

### 2. Análisis Avanzado con Filtros

Dado que las herramientas estándar fallaron, apliqué múltiples transformaciones de imagen para intentar revelar el QR code:

#### Técnicas Aplicadas:

**A) Separación de Canales RGB**
```python
img_array = np.array(img)
r_channel = img_array[:, :, 0]
g_channel = img_array[:, :, 1]
b_channel = img_array[:, :, 2]
```

**B) Filtros de Procesamiento**
- Escala de grises
- Binarización con Otsu
- Inversión de colores
- Aumento de contraste (CLAHE)
- **Desenfoque gaussiano** ← ¡Primer éxito!
- Erosión y dilatación

**C) Extracción de Bit Planes**
```python
for bit in range(8):
    bit_plane = ((channel >> bit) & 1) * 255
```

**D) Operaciones Lógicas**
- XOR entre canales (R⊕G, R⊕B, G⊕B, R⊕G⊕B)
- AND entre canales
- OR entre canales
- Resta entre canales

---

### 3. Primer Descubrimiento

Con **desenfoque gaussiano (kernel 5x5)**, logré decodificar el primer QR:

```python
blurred = cv2.GaussianBlur(gray, (5, 5), 0)
decoded = pyzbar.decode(Image.open("qr_blurred.png"))
```

**URL encontrada:**
```
https://qr.ctf.cert.unlp.edu.ar/s0m3incr3d1bl3r4nd0md4t4
```

**Respuesta del servidor:**
```
No flag for you. Scan again :)
```

Este mensaje confirmó la pista de "suerte" - había que seguir buscando.

---

### 4. Búsqueda Exhaustiva de QR Codes Ocultos

Implementé un script exhaustivo (`exhaustive_search.py`) que probó:

1. **Todos los umbrales de binarización** (0-255 en pasos de 5)
2. **Diferentes niveles de desenfoque** (kernels de 1x1 a 21x21)
3. **Operaciones morfológicas** con múltiples tamaños de kernel:
   - Erosión
   - Dilatación
   - Opening
   - **Closing** ← ¡Clave del éxito!
   - Gradient
   - Top-hat

```python
for kernel_size in range(1, 6):
    kernel = np.ones((kernel_size, kernel_size), np.uint8)
    
    # Closing morfológico
    closing = cv2.morphologyEx(binary, cv2.MORPH_CLOSE, kernel)
    cv2.imwrite(f"temp_close_{kernel_size}.png", closing)
    
    # Intentar decodificar
    decoded = pyzbar.decode(Image.open(f"temp_close_{kernel_size}.png"))
```

---

### 5. Detección de Múltiples QR Codes

Utilicé **QReader**, una librería más avanzada que puede detectar múltiples QR codes superpuestos:

```python
from qreader import QReader

qreader = QReader(model_size='l')
img = cv2.imread("qr.png")
results = qreader.detect_and_decode(image=img, return_detections=True)
```

**QReader confirmó:** La imagen contenía **2 QR codes superpuestos**.

---

### 6. Hallazgo del Segundo QR Code

Al procesar todas las variaciones con QReader, encontré que dos transformaciones específicas revelaban una URL diferente:

**Transformación 1:** Morphological Closing con kernel=3
```python
kernel = np.ones((3, 3), np.uint8)
closing = cv2.morphologyEx(binary, cv2.MORPH_CLOSE, kernel)
```

**Transformación 2:** Binarización con threshold=240
```python
_, binary = cv2.threshold(gray, 240, 255, cv2.THRESH_BINARY)
```

**Segunda URL encontrada:**
```
https://qr.ctf.cert.unlp.edu.ar/50m3incr3d1bl3r4nd0md4t4
```

Nota la diferencia: **`50m3`** en lugar de **`s0m3`** (5 en lugar de s)

---

### 7. Obtención de la Flag

Al acceder a la segunda URL:

```bash
curl https://qr.ctf.cert.unlp.edu.ar/50m3incr3d1bl3r4nd0md4t4
```

**Respuesta:**
```
Lucky guy! this flag is for you: UNLP{DualQR_C0d3s_4r3_Aw3s0m3!}
```

---

## Resumen Técnico

### URLs Encontradas

| QR Code | Procesamiento Necesario | URL | Resultado |
|---------|------------------------|-----|-----------|
| QR #1 (señuelo) | Desenfoque gaussiano, múltiples thresholds | `s0m3incr3d1bl3r4nd0md4t4` | "No flag for you. Scan again :)" |
| QR #2 (flag) | Closing morfológico (k=3) o Threshold=240 | `50m3incr3d1bl3r4nd0md4t4` | Flag real |

### Concepto de "Suerte"

El mensaje de "depende de tu suerte" se refería a:
1. Tener la suerte de aplicar el filtro correcto entre cientos de posibilidades
2. Los dos QR codes estaban superpuestos de tal forma que solo ciertos procesamientos morfológicos revelaban el segundo

### Herramientas Clave

1. **pyzbar** - Decodificación básica de QR
2. **OpenCV** - Procesamiento de imágenes y operaciones morfológicas
3. **QReader** - Detección avanzada de múltiples QR codes
4. **PIL/Pillow** - Manipulación de imágenes

---

## Scripts Desarrollados

### 1. `decode_qr.py`
Decodificación básica con pyzbar y OpenCV.

### 2. `advanced_decode.py`
Separación de canales RGB, aplicación de filtros, verificación de esteganografía LSB.

### 3. `exhaustive_search.py`
Búsqueda exhaustiva probando:
- 51 valores de threshold diferentnes
- 10 niveles de desenfoque
- 5 tamaños de kernel con 4 operaciones morfológicas
- 9 combinaciones de operaciones lógicas entre canales

**Total:** >200 variaciones de imagen procesadas

### 4. `qreader_deep.py`
Análisis profundo con QReader, extracción de regiones individuales de cada QR detectado.

### 5. `advanced_multi_qr.py`
Extracción de bit planes, combinaciones XOR, restas entre canales.

---

## Conclusión

El reto era un excelente ejemplo de **esteganografía visual mediante superposición de QR codes**. La clave estaba en:

1. **Persistencia:** Probar múltiples técnicas de procesamiento de imagen
2. **Automatización:** Crear scripts que probaran sistemáticamente todas las variaciones
3. **Herramientas avanzadas:** Usar QReader para confirmar la presencia de múltiples QR codes
4. **Análisis de respuestas:** El mensaje "Scan again :)" era una pista clara de que había más QR codes ocultos

---

## Flag Final

```
UNLP{DualQR_C0d3s_4r3_Aw3s0m3!}
```

**Fecha de resolución:** 2025-12-04  
**Tiempo estimado:** ~25 minutos  
**Dificultad:** Media (requiere conocimientos de procesamiento de imágenes)
