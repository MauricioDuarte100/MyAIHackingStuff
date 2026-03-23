#!/usr/bin/env python3
import argparse
import subprocess
import threading
import time
import os
import sys

# Windows/AD CTF Swarm Orchestrator (v1.0)
# Designed by Antigravity for Hack The Box / Active Directory Targets
# Leverages the 'ad-pentesting-elite' logic for parallel enumeration

def run_cmd(agent_name, cmd, output_file=None):
    print(f"[{agent_name}] Iniciando: {cmd}")
    start_time = time.time()
    try:
        if output_file:
            with open(output_file, 'w') as f:
                process = subprocess.Popen(cmd, shell=True, stdout=f, stderr=subprocess.STDOUT)
        else:
            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        
        process.wait()
        end_time = time.time()
        print(f"[+] {agent_name} finalizado en {end_time - start_time:.2f} segundos.")
    except Exception as e:
        print(f"[!] {agent_name} falló: {e}")

def run_windows_swarm(ip, output_dir):
    print(f"\n🪟 Iniciando Swarm Windows/AD para CTF en: {ip}")
    os.makedirs(output_dir, exist_ok=True)
    
    # 1. Nmap Full TCP Scan
    cmd_nmap_fast = f"nmap -p- --min-rate 10000 {ip} -Pn -n -oG {output_dir}/nmap_all_ports.txt"
    # 2. NetExec / CrackMapExec (SMB/WinRM Null Session check)
    cmd_netexec = f"netexec smb {ip} -u '' -p '' --shares --sessions --users > {output_dir}/netexec_smb_null.txt"
    # 3. LDAP Search (Anonymous Bind)
    cmd_ldap = f"ldapsearch -x -H ldap://{ip} -b 'DC=local,DC=local' -s sub 'objectclass=*' > {output_dir}/ldap_anonymous.txt 2>/dev/null || echo 'LDAP Null Session Failed' > {output_dir}/ldap_anonymous.txt"
    # 4. Web Fuzzing (IIS - puertos 80/443 comunes)
    cmd_ferox = f"feroxbuster -u http://{ip} --silent --wordlist /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -x txt,aspx,config -o {output_dir}/web_feroxbuster.txt"

    print("[*] Lanzando Drones Paralelos para Windows (Nmap AllPorts + NetExec SMB + LDAP Enum + IIS Fuzzing)...")
    
    threads = []
    threads.append(threading.Thread(target=run_cmd, args=("Nmap All-Ports Drone", cmd_nmap_fast)))
    threads.append(threading.Thread(target=run_cmd, args=("NetExec Null Session Drone", cmd_netexec)))
    threads.append(threading.Thread(target=run_cmd, args=("LDAP Anonymous Drone", cmd_ldap)))
    threads.append(threading.Thread(target=run_cmd, args=("Feroxbuster IIS Drone", cmd_ferox)))
    
    for t in threads:
        t.start()
    for t in threads:
        t.join()
        
    print(f"\n✅ Swarm Windows Finalizado. Analiza los vectores en {output_dir}/")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Antigravity: Windows/AD CTF Swarm Orchestrator")
    parser.add_argument("-i", "--ip", required=True, help="IP objetivo de la máquina Windows / Domain Controller")
    parser.add_argument("-o", "--output", required=True, help="Directorio de salida para los reportes de los drones")
    
    args = parser.parse_args()
    run_windows_swarm(args.ip, args.output)
