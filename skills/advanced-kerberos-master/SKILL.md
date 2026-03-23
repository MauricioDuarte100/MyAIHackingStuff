# Advanced Kerberos Master

Especialista en advanced-kerberos-master

## Instructions
Eres un experto de élite en advanced-kerberos-master. Tu objetivo es ejecutar la siguiente metodología con precisión quirúrgica y eficiencia técnica.

---
name: advanced-kerberos-master
description: Dominio de RBCD, U2U, Shadow Credentials y ataques de certificados ADCS (ESC1-ESC11). Especializado en evadir la falta de SPN y errores de sincronización horaria.
---

# Advanced Kerberos Master (AKM)

## 1. RBCD + U2U: EL ATAQUE DEFINITIVO SIN SPN
Cuando una cuenta de máquina no tiene SPN, el ataque S4U2Self falla. Esta habilidad permite el uso de User-to-User (U2U).

### 1.1 Metodología de Sincronización de Claves
Este es el truco avanzado usado en máquinas como Hercules:
1. Obtener el TGT de la máquina objetivo.
2. Extraer la "Ticket Session Key" del ticket de la máquina.
3. Cambiar el Hash NT de la máquina para que sea IGUAL a la Session Key.
4. Solicitar el Service Ticket (ST) con el flag `-u2u`.

### 1.2 Código de Automatización (Python)
```python
# Ejemplo de sincronización de claves para U2U
def sync_machine_key(session_key, machine_name):
    print(f"[*] Sincronizando clave para {machine_name}")
    cmd = f"impacket-changepasswd -newhashes :{session_key} ..."
    return cmd
```

## 2. SHADOW CREDENTIALS (MSDS-KEYCREDENTIALLINK)
Permite autenticación persistente sin cambiar la contraseña.
- **Workflow**: `GenericWrite` -> Inyectar Key -> PKINIT -> TGT.
- **Herramientas**: `certipy-ad shadow auto`.

## 3. AD CS (ESC1-ESC11)
- **ESC1**: SAN en plantilla vulnerable.
- **ESC8**: NTLM Relay a AD CS HTTP endpoints.
- **Bypass**: Usar `-dcom` cuando RPC está bloqueado.

## 4. TROUBLESHOOTING
- **KRB_AP_ERR_SKEW**: Error de tiempo. Usar `LD_PRELOAD=libfaketime.so.1`.
- **KDC_ERR_S_PRINCIPAL_UNKNOWN**: SPN inexistente. Forzar U2U.

## Available Resources
- . (Directorio de la skill)
