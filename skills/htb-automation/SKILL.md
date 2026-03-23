# Htb Automation

Especialista en htb-automation

## Instructions
Eres un experto de élite en htb-automation. Tu objetivo es ejecutar la siguiente metodología con precisión quirúrgica y eficiencia técnica.

---
name: htb-automation
description: |
  Automates the initial setup for HackTheBox/CTF machines. 
  Creates standardized workspace directories, generates /etc/hosts injection commands,
  and runs high-speed "Turbo" Nmap scans to find open ports in seconds.
version: 1.0.0
author: Gemini
domain: ctf/automation
difficulty: basic
prerequisites:
  - nmap
  - sudo access (for /etc/hosts)
---

# HTB Automation & Turbo Start

## 1. Fast Start (Workspace & Networking)

**Trigger:** "Start machine <name> at <ip>" or "Setup HTB box <name>"

**Actions:**
1.  **Directory Structure:**
    *   Create: `<name>/scans`, `<name>/exploit`, `<name>/loot`, `<name>/content`.
    *   Move into `<name>`.

2.  **Network Setup (/etc/hosts):**
    *   Generate the command to map the IP to `name.htb`.
    *   *Agent Output:* "Run this to set up DNS: `echo '<ip> <name>.htb' | sudo tee -a /etc/hosts`"

## 2. Turbo Nmap Scan (The "Beast" Mode)

**Trigger:** "Scan ports for <ip>" or "Run turbo nmap"

**Methodology:**
1.  **Phase 1: Discovery ( TCP SYN - Min Rate 5000)**
    *   Scans all 65535 ports in ~20 seconds.
    *   Command: `nmap -p- --min-rate=5000 -sS -Pn -v -n <ip> -oG scans/all_ports.log`
    
2.  **Phase 2: Extraction**
    *   Extract open ports from the log.
    *   Command: `grep Open scans/all_ports.log | cut -d ' ' -f 2 | tr '\n' ','`
    
3.  **Phase 3: Deep Scan (Targeted)**
    *   Runs Script and Version scan ONLY on found ports.
    *   Command: `nmap -p<ports> -sC -sV -Pn <ip> -oN scans/targeted.nmap`

## 3. Automation Scripts provided

### `start_box.sh` (Template)
```bash
#!/bin/bash
NAME=$1
IP=$2

if [ -z "$NAME" ] || [ -z "$IP" ]; then
    echo "Usage: $0 <name> <ip>"
    exit 1
fi

mkdir -p $NAME/{scans,exploit,loot,content}
echo "[+] Folders created."

echo "[*] Add this to hosts:"
echo "echo '$IP $NAME.htb' | sudo tee -a /etc/hosts"

echo "[*] Running Turbo Scan..."
nmap -p- --min-rate=5000 -sS -Pn -v -n $IP -oG $NAME/scans/all_ports.log
# Note: This is an example, real extraction logic may vary
PORTS=$(grep "Status: Open" $NAME/scans/all_ports.log | cut -d ' ' -f 2 | tr '\n' ',')
if [ -z "$PORTS" ]; then
    echo "[-] No ports found."
else
    echo "[+] Ports found: $PORTS"
    nmap -p${PORTS%,} -sC -sV -Pn $IP -oN $NAME/scans/targeted.nmap
fi
```


## Available Resources
- . (Directorio de la skill)
