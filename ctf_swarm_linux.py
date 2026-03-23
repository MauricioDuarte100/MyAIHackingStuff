#!/usr/bin/env python3
import argparse
import subprocess
import threading
import time
import os
import sys

# Linux CTF Swarm Orchestrator (v1.0)
# Designed by Antigravity for Hack The Box / VulnHub (Linux Targets)

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

def run_linux_swarm(ip, output_dir):
    print(f"\n🐧 Iniciando Swarm Linux para CTF en: {ip}")
    os.makedirs(output_dir, exist_ok=True)
    
    # 1. Nmap Full TCP Scan (Agresivo, rápido)
    cmd_nmap_fast = f"nmap -p- --min-rate 10000 {ip} -Pn -n -oG {output_dir}/nmap_all_ports.txt"
    # 2. Web Fuzzing (Asume puerto 80 por defecto, pero escalable)
    cmd_ferox = f"feroxbuster -u http://{ip} --silent --wordlist /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -o {output_dir}/web_feroxbuster.txt"
    # 3. Enum4Linux-ng (Para SMB y RPC - vital en Linux)
    cmd_enum4linux = f"enum4linux-ng -A -R {ip} > {output_dir}/smb_enum4linux.txt"
    # 4. Nmap Vulnerability Scripts (Corriendo de fondo sobre puertos comunes)
    cmd_nmap_vuln = f"nmap -sV -sC -p 21,22,80,443,445,3306,8080 --script=vuln {ip} -Pn -oN {output_dir}/nmap_vuln_scan.txt"

    print("[*] Lanzando Drones Paralelos para Linux (Nmap AllPorts + Web Fuzzing + SMB/RPC Enum + Vuln Scan)...")
    
    threads = []
    threads.append(threading.Thread(target=run_cmd, args=("Nmap All-Ports Drone", cmd_nmap_fast)))
    threads.append(threading.Thread(target=run_cmd, args=("Feroxbuster Web Drone", cmd_ferox)))
    threads.append(threading.Thread(target=run_cmd, args=("Enum4Linux Drone", cmd_enum4linux)))
    threads.append(threading.Thread(target=run_cmd, args=("Nmap Vuln Drone", cmd_nmap_vuln)))
    
    for t in threads:
        t.start()
    for t in threads:
        t.join()
        
    print(f"\n✅ Swarm Linux Finalizado. Analiza los vectores en {output_dir}/")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Antigravity: Linux CTF Swarm Orchestrator")
    parser.add_argument("-i", "--ip", required=True, help="IP objetivo de la máquina Linux")
    parser.add_argument("-o", "--output", required=True, help="Directorio de salida para los reportes de los drones")
    
    args = parser.parse_args()
    run_linux_swarm(args.ip, args.output)
