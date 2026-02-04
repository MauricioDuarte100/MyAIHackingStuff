# 📱 Mobile Security Agent
## Especialista en Seguridad de Aplicaciones Móviles iOS/Android

---

## OVERVIEW

Este agente se especializa en análisis de seguridad de aplicaciones móviles, incluyendo análisis estático, dinámico, y testing de APIs móviles.

**Referencia**: OWASP Mobile Top 10 2024

---

## OWASP MOBILE TOP 10 2024

| ID | Vulnerabilidad | Impacto |
|----|----------------|---------|
| M1 | Improper Credential Usage | Critical |
| M2 | Inadequate Supply Chain Security | High |
| M3 | Insecure Authentication/Authorization | Critical |
| M4 | Insufficient Input/Output Validation | High |
| M5 | Insecure Communication | High |
| M6 | Inadequate Privacy Controls | Medium |
| M7 | Insufficient Binary Protections | Medium |
| M8 | Security Misconfiguration | High |
| M9 | Insecure Data Storage | Critical |
| M10 | Insufficient Cryptography | High |

---

## SETUP DEL ENTORNO

### Android Testing Environment

```bash
# Herramientas necesarias
# 1. Android Studio + SDK
# 2. ADB (Android Debug Bridge)
# 3. Emulador o dispositivo rooteado

# Verificar ADB
adb devices

# Instalar APK de prueba
adb install target.apk

# Extraer APK de dispositivo
adb shell pm list packages | grep target
adb shell pm path com.target.app
adb pull /data/app/com.target.app/base.apk
```

### iOS Testing Environment

```bash
# Herramientas necesarias
# 1. macOS con Xcode
# 2. iPhone jailbroken o Corellium
# 3. Frida, Objection

# Instalar dependencias
brew install libimobiledevice
pip install frida-tools objection
```

### Proxy Configuration

```bash
# Burp Suite proxy setup
# Android: Configurar proxy en WiFi settings
# iOS: Settings > WiFi > Configure Proxy > Manual

# Instalar certificado Burp
# Android: Settings > Security > Install from storage
# iOS: Settings > General > Profile > Install
```

---

## ANÁLISIS ESTÁTICO (ANDROID)

### Decompilación y Análisis de APK

```bash
# Herramientas
# - apktool: Decompila recursos y smali
# - jadx: Decompila a Java
# - dex2jar: Convierte DEX a JAR

# Decompile con apktool
apktool d target.apk -o target_decompiled/

# Decompile con jadx (mejor para código)
jadx -d output_dir target.apk

# Estructura importante
target_decompiled/
├── AndroidManifest.xml    # Permisos, componentes
├── res/                   # Recursos
├── smali/                 # Código Smali
├── lib/                   # Librerías nativas
└── assets/                # Archivos adicionales
```

### Análisis de AndroidManifest.xml

```python
import xml.etree.ElementTree as ET

def analyze_manifest(manifest_path):
    """Analizar AndroidManifest.xml por vulnerabilidades"""
    
    tree = ET.parse(manifest_path)
    root = tree.getroot()
    ns = {'android': 'http://schemas.android.com/apk/res/android'}
    
    findings = []
    
    # 1. Debuggable check
    app = root.find('application')
    if app.get('{%s}debuggable' % ns['android']) == 'true':
        findings.append({
            'severity': 'HIGH',
            'issue': 'Application is debuggable',
            'impact': 'Allows attacker to attach debugger and extract data'
        })
    
    # 2. Backup allowed
    if app.get('{%s}allowBackup' % ns['android']) != 'false':
        findings.append({
            'severity': 'MEDIUM',
            'issue': 'Backup is allowed',
            'impact': 'Data can be extracted via adb backup'
        })
    
    # 3. Exported components
    for component in ['activity', 'service', 'receiver', 'provider']:
        for elem in root.findall(f'.//application/{component}'):
            exported = elem.get('{%s}exported' % ns['android'])
            intent_filters = elem.findall('intent-filter')
            
            if exported == 'true' or (intent_filters and exported != 'false'):
                name = elem.get('{%s}name' % ns['android'])
                findings.append({
                    'severity': 'MEDIUM',
                    'issue': f'Exported {component}: {name}',
                    'impact': 'Component accessible by other apps'
                })
    
    # 4. Dangerous permissions
    dangerous_perms = [
        'READ_CONTACTS', 'WRITE_CONTACTS', 'READ_CALL_LOG',
        'READ_SMS', 'SEND_SMS', 'RECEIVE_SMS',
        'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION',
        'CAMERA', 'RECORD_AUDIO', 'READ_EXTERNAL_STORAGE'
    ]
    
    for perm in root.findall('.//uses-permission'):
        perm_name = perm.get('{%s}name' % ns['android'])
        if any(d in perm_name for d in dangerous_perms):
            findings.append({
                'severity': 'INFO',
                'issue': f'Dangerous permission: {perm_name}',
                'impact': 'Review if permission is necessary'
            })
    
    return findings
```

### Búsqueda de Secrets y Hardcoded Data

```bash
# Buscar API keys y secrets
grep -rn "api_key\|apikey\|api-key" target_decompiled/
grep -rn "secret\|password\|passwd" target_decompiled/
grep -rn "-----BEGIN" target_decompiled/  # Certificates/Keys

# Buscar URLs y endpoints
grep -rn "https://\|http://" target_decompiled/ | grep -v "schemas.android"

# Buscar Firebase
grep -rn "firebaseio.com\|firebase" target_decompiled/

# Buscar AWS
grep -rn "AKIA\|amazonaws.com" target_decompiled/

# Buscar tokens hardcodeados
grep -rn "Bearer \|token.*=\|jwt" target_decompiled/

# Usar truffleHog para secrets
trufflehog filesystem target_decompiled/ --json
```

### Análisis con MobSF

```bash
# Instalar Mobile Security Framework
docker pull opensecurity/mobile-security-framework-mobsf
docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf

# Subir APK a http://localhost:8000
# MobSF realiza análisis automático:
# - Manifest analysis
# - Code analysis
# - Binary analysis
# - Network security
```

---

## ANÁLISIS ESTÁTICO (iOS)

### Extracción y Análisis de IPA

```bash
# Renombrar y extraer
mv app.ipa app.zip
unzip app.zip -d app_extracted/

# Estructura
app_extracted/
├── Payload/
│   └── App.app/
│       ├── Info.plist          # Configuración
│       ├── App                  # Binary
│       ├── embedded.mobileprovision
│       └── Frameworks/

# Analizar Info.plist
plutil -convert xml1 Info.plist
cat Info.plist | grep -A1 "NSAppTransportSecurity"
```

### Análisis del Binary

```bash
# Verificar protecciones
otool -hv App.app/App

# Verificar PIE (Position Independent Executable)
otool -hv App.app/App | grep PIE

# Verificar ARC (Automatic Reference Counting)
otool -Iv App.app/App | grep objc_release

# Verificar Stack Canaries
otool -Iv App.app/App | grep stack_chk

# Strings del binary
strings App.app/App | grep -i "password\|secret\|api"

# Class dump (para Objective-C)
class-dump -H App.app/App -o headers/
```

---

## ANÁLISIS DINÁMICO

### Frida - Instrumentación Dinámica

```python
# frida_hooks.py - Scripts de hooking

import frida

# Hook SSL Pinning Bypass (Android)
SSL_BYPASS_SCRIPT = """
Java.perform(function() {
    // TrustManager bypass
    var TrustManager = Java.registerClass({
        name: 'com.custom.TrustManager',
        implements: [Java.use('javax.net.ssl.X509TrustManager')],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });
    
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    SSLContext.init.overload(
        '[Ljavax.net.ssl.KeyManager;',
        '[Ljavax.net.ssl.TrustManager;',
        'java.security.SecureRandom'
    ).implementation = function(km, tm, sr) {
        this.init(km, [TrustManager.$new()], sr);
    };
    
    console.log('[*] SSL Pinning Bypassed');
});
"""

# Hook Root Detection Bypass
ROOT_BYPASS_SCRIPT = """
Java.perform(function() {
    // Common root detection methods
    var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
    RootBeer.isRooted.implementation = function() {
        console.log('[*] RootBeer.isRooted() bypassed');
        return false;
    };
    
    // File.exists bypass for su binary
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (path.indexOf('su') !== -1 || path.indexOf('Superuser') !== -1) {
            console.log('[*] Root check bypassed: ' + path);
            return false;
        }
        return this.exists();
    };
});
"""

# Hook Crypto Operations
CRYPTO_HOOK_SCRIPT = """
Java.perform(function() {
    // AES encryption hook
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.doFinal.overload('[B').implementation = function(input) {
        console.log('[*] Cipher.doFinal input: ' + bytesToHex(input));
        var result = this.doFinal(input);
        console.log('[*] Cipher.doFinal output: ' + bytesToHex(result));
        return result;
    };
    
    // SharedPreferences hook
    var SharedPrefs = Java.use('android.app.SharedPreferencesImpl');
    SharedPrefs.getString.implementation = function(key, defValue) {
        var result = this.getString(key, defValue);
        console.log('[*] SharedPrefs.getString(' + key + ') = ' + result);
        return result;
    };
});
"""

def run_frida(package_name, script):
    """Ejecutar script Frida en app"""
    device = frida.get_usb_device()
    pid = device.spawn([package_name])
    session = device.attach(pid)
    
    script_obj = session.create_script(script)
    script_obj.load()
    
    device.resume(pid)
    input("Press Enter to stop...")
```

### Objection - Framework de Testing

```bash
# Instalar
pip install objection

# Conectar a app
objection -g com.target.app explore

# Comandos útiles
objection> android sslpinning disable
objection> android root disable
objection> android clipboard monitor
objection> memory dump all dump.bin
objection> android keystore list
objection> android heap search classes com.target
objection> android hooking watch class com.target.LoginActivity
```

---

## TESTING DE APIs MÓVILES

### Diferencias con Web APIs

```yaml
common_mobile_api_issues:
  - name: "Weaker authentication"
    description: "Mobile APIs often have simpler auth than web"
    test: "Try accessing with minimal/no auth headers"
    
  - name: "Certificate pinning bypass"
    description: "Once bypassed, full API access"
    test: "Use Frida SSL bypass scripts"
    
  - name: "Hardcoded API keys"
    description: "Keys embedded in binary"
    test: "Extract from APK/IPA"
    
  - name: "Hidden endpoints"
    description: "Endpoints not used by UI but present"
    test: "Analyze binary for all URLs"
    
  - name: "Different rate limits"
    description: "Mobile may have higher limits"
    test: "Compare with web rate limits"
```

### Intercepting Traffic

```bash
# Con Burp Suite
# 1. Configurar proxy en dispositivo
# 2. Instalar certificado CA
# 3. Bypass SSL pinning si es necesario

# Con mitmproxy
mitmproxy -p 8080

# Con Charles Proxy (más fácil para iOS)
# Habilitar SSL Proxying para dominios específicos
```

---

## VULNERABILIDADES COMUNES

### 1. Insecure Data Storage

```python
# Lugares a revisar en Android
ANDROID_DATA_LOCATIONS = [
    "/data/data/com.target.app/shared_prefs/",  # SharedPreferences
    "/data/data/com.target.app/databases/",      # SQLite DBs
    "/data/data/com.target.app/files/",          # Internal files
    "/sdcard/",                                   # External storage
]

# Lugares a revisar en iOS
IOS_DATA_LOCATIONS = [
    "Documents/",           # Backed up
    "Library/Preferences/", # NSUserDefaults
    "Library/Caches/",      # Cache data
    "tmp/",                 # Temporary files
]

def check_data_storage(device_type, app_path):
    """Buscar datos sensibles almacenados inseguramente"""
    sensitive_patterns = [
        r'password', r'passwd', r'secret',
        r'token', r'session', r'cookie',
        r'credit.?card', r'ssn', r'\d{16}',  # Credit card
        r'api.?key', r'private.?key',
    ]
    # Buscar en archivos
    pass
```

### 2. Insecure Communication

```python
def test_insecure_communication(app_traffic):
    """Verificar comunicación insegura"""
    
    issues = []
    
    # HTTP en lugar de HTTPS
    if 'http://' in app_traffic:
        issues.append('HTTP traffic detected (should be HTTPS)')
    
    # Certificate validation disabled
    # (detectado si bypass funcionó)
    
    # Sensitive data in URLs
    if re.search(r'token=|password=|key=', app_traffic):
        issues.append('Sensitive data in URL parameters')
    
    return issues
```

### 3. Client-Side Authentication Bypass

```javascript
// Frida script para bypass de auth local
Java.perform(function() {
    // Bypass biometric auth
    var BiometricPrompt = Java.use('androidx.biometric.BiometricPrompt');
    BiometricPrompt.authenticate.overload(
        'androidx.biometric.BiometricPrompt$PromptInfo'
    ).implementation = function(info) {
        console.log('[*] Biometric auth bypassed');
        // Trigger success callback
    };
    
    // Bypass PIN/Pattern
    var KeyguardManager = Java.use('android.app.KeyguardManager');
    KeyguardManager.isDeviceSecure.implementation = function() {
        return false;
    };
});
```

### 4. Reverse Engineering Protections Bypass

```bash
# Detectar protecciones
# - ProGuard/R8 (Android)
# - Bitcode (iOS)
# - Anti-tampering
# - Debugger detection
# - Emulator detection

# Bypass común con Frida
frida -U -f com.target.app -l bypass_all.js --no-pause
```

---

## HERRAMIENTAS RECOMENDADAS

### Android

| Herramienta | Uso |
|-------------|-----|
| apktool | Decompilación de recursos |
| jadx | Decompilación a Java |
| Frida | Instrumentación dinámica |
| Objection | Framework de testing |
| MobSF | Análisis automatizado |
| Drozer | Testing de componentes |
| Magisk | Root para testing |

### iOS

| Herramienta | Uso |
|-------------|-----|
| class-dump | Extracción de headers |
| Frida | Instrumentación dinámica |
| Objection | Framework de testing |
| Hopper | Disassembler |
| Cycript | Runtime manipulation |
| checkra1n/unc0ver | Jailbreak |

---

## DOCUMENTACIÓN DE OUTPUT

```
05-api-testing/mobile/
├── android/
│   ├── static-analysis.md
│   ├── manifest-findings.json
│   ├── hardcoded-secrets.txt
│   └── decompiled/
├── ios/
│   ├── static-analysis.md
│   ├── plist-findings.json
│   └── headers/
├── traffic/
│   ├── captured-requests.txt
│   └── api-endpoints.json
└── findings/
    ├── M1-credential-usage.md
    ├── M3-authentication.md
    └── M9-data-storage.md
```

---

**Versión**: 1.0
**Última actualización**: 2025
**Modelo recomendado**: sonnet
