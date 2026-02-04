# Writeup – Reto: Ecos de Guerra

## Descripción del Reto
El reto consistía en analizar un archivo de audio llamado `crypto_audio.wav` que, al escucharse normalmente, no revelaba información útil. El objetivo era identificar a qué saga pertenecía el contenido oculto.

## Análisis Inicial
Al revisar el archivo `README.txt`, se encontraron las siguientes pistas:
- "No todo se revela al escucharse."
- "Lo que parece ruido esconde una forma."
- "Pista: No todo el audio se interpreta con los oídos."

Estas pistas sugerían que el mensaje estaba oculto de forma visual dentro del audio, probablemente mediante un **espectrograma**.

## Resolución

### 1. Generación del Espectrograma
Para visualizar las frecuencias del audio, se utilizó un script en Python aprovechando las librerías `scipy`, `matplotlib` y `numpy`.

```python
import scipy.io.wavfile
import matplotlib.pyplot as plt
import numpy as np

# Cargar el archivo de audio
sample_rate, data = scipy.io.wavfile.read('crypto_audio.wav')

# Usar solo un canal si es estéreo
if len(data.shape) > 1:
    data = data[:, 0]

# Crear el espectrograma
plt.figure(figsize=(12, 6))
plt.specgram(data, Fs=sample_rate, NFFT=1024, noverlap=512)
plt.title('Spectrogram of crypto_audio.wav')
plt.ylabel('Frecuencia')
plt.xlabel('Tiempo')
plt.colorbar()
plt.savefig('spectrogram.png')
```

### 2. Identificación Visual
Al ejecutar el script y generar el archivo `spectrogram.png`, se observó una imagen oculta en las frecuencias del audio. La imagen mostraba claramente a **Kratos**, el protagonista de la saga **God of War**.

### 3. Flag
Siguiendo el formato solicitado `FLAG{NOMBRE_DE_LA_SAGA}`, se determinó que la flag era:

**FLAG{GOD_OF_WAR}**
