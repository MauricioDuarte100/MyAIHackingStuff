---
description: How to perform automated reconnaissance using the master script
---

# 🚀 Automated Reconnaissance Workflow

This workflow automates the process of mapping a target's attack surface using the `scripts/recon_master.sh` script.

## 📋 Steps

### 1. Identify Target
Decide on the root domain you want to map (e.g., `example.com`).

### 2. Run the Recon Master Script
// turbo
Execute the script with the target domain. You can optionally provide a wordlist for brute-forcing.

```bash
./scripts/recon_master.sh target.com
```

*Note: If you have a specific wordlist:*
```bash
./scripts/recon_master.sh target.com /usr/share/wordlists/subdomains.txt
```

### 3. Analyze Results
The script creates a directory named `recon_target.com/` containing:
- `passive.txt`: Subdomains found via passive sources.
- `resolved.txt`: All subdomains that resolved to an IP.
- `live_assets_metadata.txt`: Metadata for active web assets (Status, Title, Tech, etc.).
- `live_urls.txt`: A clean list of active URLs.

### 4. Deep Dive into 403s/404s
Review `live_assets_metadata.txt` for 403 Forbidden assets. Use the `idor` or `dirsearch` skills to probe these further.

### 5. Network Scan (Manual)
For critical IPs found in `live_assets_metadata.txt`, run a targeted port scan:
```bash
nmap -sV -p- --min-rate 1000 <Target_IP>
```

---
**Tool Dependencies**: `subfinder`, `puredns`, `alterx`, `httpx`, `anew`, `nmap`.
**Output Location**: `./recon_<domain>/`
