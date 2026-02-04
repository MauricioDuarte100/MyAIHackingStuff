---
name: NahamSec Methodology
description: "Comprehensive, advanced Bug Bounty methodology based on NahamSec's teachings. Includes Deep Dive modules for Recon, JavaScript Analysis, Chain Attacks, and Bypass Techniques."
---

# NahamSec Bug Bounty Methodology: Advanced Edition

This skill provides a deep technical dive into bug bounty hunting, structured into four advanced modules. This content is extracted directly from expert methodologies.

## Module 1: Advanced Recon & Asset Discovery
*Focus: Vertical/Horizontal Correlation, Shadow IT, and Automation.*

### 1.1 Horizontal vs. Vertical Correlation
*   **Horizontal (Root Domains):**
    *   **ASN Mapping:** `bgp.he.net` to find all IPv4/IPv6 blocks. Scan entire ASN ranges to find shadow assets not in DNS.
    *   **Reverse WHOIS:** Use **Whoxy** or **DOMLink** to find all domains registered by `domains@target.com`.
    *   **Acquisitions:** Search "Copyright [Year] Target Inc" or use Crunchbase.
*   **Vertical (Subdomains):**
    *   **Contextual Permutations:** Use **Altdns** or **Regulator**. If you find `api.target.com`, generate `api-dev`, `api-stg`.
    *   **Recursive Iteration:** If `admin.target.com` exists, recurse for `dev.admin.target.com`.

### 1.2 Shadow IT Discovery (Shodan/Censys)
*   **Favicon Hashing:** Hash the target's favicon and query Shodan `http.favicon.hash:[HASH]` to find IP-only hosts.
*   **SSL Filtering:** Query `ssl:"Target Name"` to find self-signed certs on dev boxes.
*   **Cloud Range Scanning:** Download AWS/GCP ranges, scan port 443, and grep SSL certs for the target name to find ephemeral instances.

### 1.3 Tooling Configuration
*   **Amass:** Use `-active` for zone transfers. Increase resolvers to >5000 and max-queries to >20000.
*   **Subfinder:** Must use `provider-config.yaml` with keys (Chaos, GitHub, SecurityTrails).
*   **Axiom:** Distributed scanning. Split targets across 20+ droplets to brute-force massive ranges in minutes.

---

## Module 2: JavaScript Analysis & API Discovery
*Focus: Static Analysis, Secret Hunting, and Fuzzing.*

### 2.1 Static Analysis
*   **Manual Review:** Use **Renniepak's Bookmarklet** to dump all JS variables/endpoints from the specific page context.
*   **Source Mapping:** Use **Source Mapper** to reconstruct original file trees from `.map` files (often left in production).
*   **Keywords:** Search for `API/`, `v1/`, `swagger`, `graphql`, `access_key`, `Bearer`, `AKIA` (AWS).

### 2.2 Advanced Fuzzing
*   **Contextual Wordlists:** Do not use generic lists. Create lists from the target's own HTML/JS words.
*   **Filtering:** Filter by **Content-Length** and **Word Count** (e.g., `-fc 404 -fs 0`).
*   **403/401 Handling:** If `/admin` is 403, fuzz `/admin/FUZZ`. Often subdirectories are exposed.

---

## Module 3: Critical Vulnerability Chaining
*Focus: Escalating Low/Medium bugs to P1/P2.*

### 3.1 IDOR Chains
*   **Escalation:** IDOR -> PII Leak -> Account Takeover.
*   **Technique:** If simple IDOR works for viewing, try **modifying** (PUT/POST).
*   **Invite Logic:** Invite a user to your org, then try to modify their email address to one you control to take over the account.

### 3.2 XSS Escalation
*   **Goal:** Steal Session/Tokens or perform Actions.
*   **Technique:** Use `fetch()` payloads to hit `/api/me`, extract JSON/JWT tokens, and send to attacker.
*   **Blind XSS:** Inject into "User-Agent", "Support Tickets", "Address Fields". Use OOB payloads (interact.sh).

### 3.3 SSRF Exploitation
*   **Cloud Metadata:**
    *   AWS: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`.
    *   GCP: Requires `Metadata-Flavor: Google`. Harder, needs header injection or open redirect.
*   **Open Redirect Chain:** Use a whitelisted domain's open redirect to hit internal IPs. `whitelisted.com/redirect?url=http://169...`.

---

## Module 4: Bypass Techniques & Tricks
*Focus: WAF Evasion and Auth Bypass.*

### 4.1 403 Bypass Checklist
1.  **Headers:** `X-Forwarded-For: 127.0.0.1`, `X-Original-URL: /admin`.
2.  **Path:** `/admin/.`, `/%2e/admin`, `/admin;/`, `/admin%20`.
3.  **Methods:** Switch GET to POST/PUT, or try `X-HTTP-Method-Override`.

### 4.2 WAF Evasion
*   **Padding:** Add 8KB of junk data at the start of POST body to overflow the WAF inspection buffer.
*   **Content-Type:** Change `application/json` to `text/plain` or `application/x-www-form-urlencoded`.
*   **SQLi:** Use `/**/` for spaces, or double URL encode `%2527`.

### 4.3 OAuth Attacks
*   **Redirect URI:** Try `evil.com@target.com`, `//attacker.com`.
*   **Response Mode:** Change to `response_mode=fragment` or `web_message`.
*   **Pre-Account Takeover:** Register with victim email before they use Social Login.

---

## Payloads Reference
*See `payloads/payloads.txt` for specific injection strings.*
