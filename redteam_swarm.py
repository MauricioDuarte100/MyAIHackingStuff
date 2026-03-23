#!/usr/bin/env python3
import argparse
import subprocess
import threading
import time
import os
import sys

# Red Team Swarm Orchestrator (v1.0)
# Designed by Antigravity for Bug Bounty and CTF parallel execution
# Uses Threading to launch designated tools concurrently based on the target type.

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

def run_bugbounty_swarm(domain, output_dir):
    print(f"\n🚀 Iniciando Swarm para Bug Bounty en: {domain}")
    os.makedirs(output_dir, exist_ok=True)
    
    # 1. Asset Discovery Agent (Recon pasivo y rápido)
    cmd_subfinder = f"subfinder -d {domain} -silent > {output_dir}/subdomains.txt"
    # 2. Port & Service Discovery (Naabu/HTTPX)
    cmd_httpx = f"httpx -l {output_dir}/subdomains.txt -silent -title -status-code > {output_dir}/alive_web.txt"
    # 3. Vuln Scanner Agent (Nuclei en paralelo sobre los vivos)
    cmd_nuclei = f"nuclei -l {output_dir}/alive_web.txt -t cves/ -t exposures/ -silent > {output_dir}/nuclei_high.txt"

    # Lanzamos el Swarm (El recon debe ir primero, dependencias)
    print("[*] Lanzando Drone 1 (Recon)...")
    run_cmd("Subfinder Drone", cmd_subfinder)

    print("[*] Lanzando Drones Paralelos (HTTPX + Nuclei)...")
    t1 = threading.Thread(target=run_cmd, args=("HTTPX Drone", cmd_httpx))
    t1.start()
    t1.join() # HTTPX debe terminar para que Nuclei empiece
    
    t2 = threading.Thread(target=run_cmd, args=("Nuclei Vuln Drone", cmd_nuclei))
    # Aquí podríamos meter ffuf en paralelo
    cmd_ffuf = f"ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -u HOST/FUZZ -mc 200,403"
    print(f"[!] Fuzzing asíncrono debe realizarse iterando sobre {output_dir}/alive_web.txt")
    
    t2.start()
    t2.join()
    
    print(f"\n✅ Swarm Finalizado. Revisa los resultados en {output_dir}/")

def run_ctf_swarm(ip, output_dir):
    print(f"\n🚀 Iniciando Swarm para CTF en: {ip}")
    os.makedirs(output_dir, exist_ok=True)
    
    # 1. Nmap Fast Scan
    cmd_nmap_fast = f"nmap -p- --min-rate 5000 {ip} -Pn -n -oG {output_dir}/nmap_ports.txt"
    # 2. Rustscan / Feroxbuster (Web Deep Dive inicial en el puerto 80)
    cmd_ferox = f"feroxbuster -u http://{ip} --silent --wordlist /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -o {output_dir}/ferox.txt"
    
    print("[*] Lanzando Drones Paralelos (Nmap Agresivo + Web Craping Ciego)...")
    t1 = threading.Thread(target=run_cmd, args=("Nmap Aggressive Drone", cmd_nmap_fast))
    t2 = threading.Thread(target=run_cmd, args=("Feroxbuster Web Drone", cmd_ferox))
    
    t1.start()
    t2.start()
    
    t1.join()
    t2.join()
    print(f"\n✅ Swarm Finalizado. Revisa {output_dir}/")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Antigravity: Red Team Swarm Orchestrator")
    parser.add_argument("-t", "--type", choices=["bb", "ctf"], required=True, help="Tipo de target: bb (Bug Bounty) o ctf (Hack The Box/IP)")
    parser.add_argument("-d", "--domain", help="Dominio objetivo (para bb)")
    parser.add_argument("-i", "--ip", help="IP objetivo (para ctf)")
    parser.add_argument("-o", "--output", required=True, help="Directorio de salida para los reportes de los drones")
    
    args = parser.parse_args()
    
    if args.type == "bb" and not args.domain:
        print("[!] Requiere -d/--domain para Bug Bounty")
        sys.exit(1)
    elif args.type == "ctf" and not args.ip:
        print("[!] Requiere -i/--ip para CTF")
        sys.exit(1)
        
    if args.type == "bb":
        run_bugbounty_swarm(args.domain, args.output)
    else:
        run_ctf_swarm(args.ip, args.output)
