#!/usr/bin/env python3
import os
import sys
import argparse
import subprocess
import time
import re
import shutil
import socket
from datetime import datetime
import threading

# --- ANSI Colors ---
RED = '\033[1;31m'
YELLOW = '\033[1;33m'
GREEN = '\033[1;32m'
CYAN = '\033[1;36m'
PURPLE = '\033[1;35m'
NC = '\033[0m'

# --- Global Variables ---
START_TIME = time.time()
NMAP_PATH = shutil.which("nmap")
ALL_TCP_PORTS = ""
UDP_PORTS = ""

# --- Helper Functions ---

def print_banner():
    print(f"{GREEN}")
    print(r""" 

⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣶⣄⠀⠐⣶⣶⣶⣶⣶⡖⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣶⣶⠆⠀⠀⢀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢻⡏⢅⠄⡀⠉⢛⡙⠙⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⢄⡆⡀⠀⢀⣠⣤⣾⣿⣿⣿⡃⠀⠀⢸
⠀⡀⠀⠀⠂⠀⠀⠀⠈⢀⠀⠀⢠⣷⡏⣲⡀⣀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡐⠌⣘⣲⡄⣿⣿⣿⣿⣿⣿⣿⡅⠀⠀⠀
⣿⢕⠀⠀⠀⠀⠀⠐⠀⠋⠀⠀⢸⡟⡜⢣⣹⣿⣿⣶⣶⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡚⠃⠀⠉⢿⡧⠘⠉⠁⠈⢻⢿⣿⠆⠀⠀⠀
⡵⡾⠀⠀⠀⠀⠿⠛⠁⠀⠀⠀⠈⠀⠀⣤⣶⣶⣶⣶⣤⣀⢠⠀⠀⡀⢀⠀⡀⠀⢤⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⢀⣀⣠⣾⣇⠀⠀⠀⠀⠀⠈⠹⡃⠀⠀⠀
⣦⠁⠀⠀⢘⣦⡀⠀⠤⠒⠈⠀⠀⠀⠀⠀⢠⡀⣄⡀⣀⠀⠀⠈⠀⠉⠈⠘⠒⠛⠂⠀⠀⠀⠀⠴⣤⢢⣄⠀⠀⣄⣀⠘⠻⢿⡗⠀⠀⠀⠀⠀⠀⠀⡅⠀⠀⠀
⣟⣧⠀⠀⠼⠛⣥⡃⠄⡀⠀⠀⠀⠀⠀⠀⣮⣽⣿⣿⣿⣻⡖⣶⣼⣦⣴⣀⢀⠀⢠⠠⠄⡀⢀⠀⠀⠀⠀⠈⠉⠈⠀⠙⠀⠄⠈⠀⠀⠀⢀⣴⣶⣶⠆⠀⠀⠀
⣿⣿⡀⠀⠀⠀⣿⡹⢎⠔⠀⡀⠀⠀⠀⠴⠺⣿⣿⣿⠃⠁⠈⠈⠉⠛⠻⡹⣞⡂⢅⡊⠴⡐⢏⡟⣼⣿⣿⢦⣦⠀⠀⠀⠀⠀⠀⠀⠀⣠⣿⢸⣿⣿⡃⠀⠀⠀
⣿⣿⡆⢰⣤⡀⠙⡸⢌⡚⠄⠀⠀⠀⠀⣠⣿⣿⣿⠅⠀⠀⠀⠀⠀⠀⠀⠘⢆⠱⠀⠨⠑⠉⠀⠀⠀⠀⠀⠉⣾⠀⠀⠀⠀⠀⢰⣠⣶⣷⣾⡟⣿⣿⠇⠀⠀⠈
⣿⣿⡇⠫⣿⣿⠀⠀⠃⠜⡄⠀⠀⠀⠀⣽⣿⣿⠏⠃⠀⠀⠀⠀⠀⠀⠀⡀⡈⣔⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⡄⠀⠀⠀⠀⠈⣿⣿⣿⣿⣿⣻⣿⡇⠀⠀⠀
⣿⣿⣀⣤⣿⣿⣇⠀⠀⢰⡀⠀⠈⠄⠀⣿⣿⣿⠦⣁⠒⣶⣴⣴⡶⢼⢭⣇⠞⠁⠀⠘⡤⣀⠀⠀⠀⠀⠀⢦⣹⡇⠀⠀⠀⡜⠀⣿⡿⠛⣵⣿⣿⣿⡆⠀⠀⠀
⣿⣿⣿⣅⠀⠚⣿⡆⠀⠢⠄⠀⠀⢂⠀⣿⣿⣿⢰⢩⡙⣾⣿⣿⢯⣯⣿⠇⠀⠀⠀⠀⢰⢩⣿⠇⠀⣀⠉⠢⢵⡇⠀⠀⡘⠄⠐⠋⣠⣾⣿⣿⣿⣿⠆⠀⠀⠀
⣿⣿⣿⣿⣧⣠⣼⣿⠀⢀⠂⠀⠀⠀⢂⠙⢍⠣⣋⢧⣝⣾⣿⣿⣿⣿⡏⠀⠀⠀⠀⠀⢨⣹⢎⠀⢦⠑⢢⡙⡼⠀⠀⡐⠀⠀⢀⣼⣿⣿⣿⣿⣿⣿⡇⠀⠀⢈
⣿⣿⣿⣿⣿⣿⣧⠥⢭⣤⣤⠀⠀⠀⠢⠀⠀⠀⠀⠜⣿⣿⣿⡏⣿⣿⠟⣀⠠⢢⠄⡀⢤⣛⡎⠜⠢⠉⠂⠁⠀⠀⠐⠀⠀⡀⣿⣿⣿⣿⣿⣿⣿⣿⡷⡇⠀⠀
⣿⣿⣿⣿⣿⣿⢱⢃⠀⠉⠃⠀⠀⠀⠀⡃⠀⠀⠀⠀⠾⣿⣿⢱⡧⡇⠀⡣⠘⡁⠂⠴⢸⣟⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣱⣿⣿⣿⣿⣿⣿⣿⣿⡇⠄⠀⠀
⣿⣿⣿⣿⣿⣿⣎⢧⠂⠀⠀⠀⠀⠀⠀⠰⠁⠀⠀⠀⠀⣯⢋⡎⡑⣁⢐⡑⣀⠃⡘⠠⣻⠍⠀⠀⠀⠀⢠⣶⣶⡖⠀⣀⣤⣛⠻⣿⣿⣿⣿⣿⣿⣿⠆⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣯⡣⡅⡀⠀⠀⠱⣀⠀⠑⠀⠀⠀⠀⠀⡇⢨⠀⠃⠈⠃⠘⠐⠂⠂⠒⠀⠀⠀⠀⠀⠀⢻⣿⠀⢼⣿⣿⣿⣿⣦⡙⢿⣿⣿⣿⣿⡃⠀⠀⢀
⠙⣿⠿⡿⢿⣿⣿⣿⣷⣜⠡⣆⡀⠀⠀⠈⠄⠠⠀⠀⠀⠀⡏⡔⠰⠀⠆⡄⢀⠀⡘⠐⠀⠀⠀⠀⠀⠀⠠⣌⢿⠀⣼⣿⣿⣿⣿⣿⠿⢸⣿⣿⣿⣿⠄⠀⠀⠀
⠀⠀⠀⠃⢫⣿⣿⣿⣿⣿⣷⠆⠹⢤⡀⠀⠀⠀⠈⠀⠃⠄⠀⠁⠀⠘⠀⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠌⠎⢀⣿⣿⣿⣿⠟⣡⣾⣿⣿⣿⣿⣿⠂⠀⠀⠀
⠀⠀⠀⠀⠀⠈⠙⠿⢿⣿⣿⣾⢁⠀⠉⠣⠄⠀⠀⠀⠀⠆⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⣿⡿⠛⠰⠿⠁⠀⠉⢹⣿⣿⠁⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠫⣭⣓⠏⠤⢠⡊⠑⣠⡀⠀⠀⠀⠁⠀⠰⠀⠀⢀⠀⠀⠀⠀⠀⠀⠀⠂⠄⠀⠀⠀⠀⠉⠋⠁⠀⠀⠀⠀⠀⠀⠈⢟⡿⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠐⡠⠀⠀⠈⠛⢿⣶⣬⡖⠁⠄⠳⠆⣀⠀⠀⠀⠀⠀⠀⠈⠀⠀⡐⠀⠡⠀⠀⠀⠠⠀⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡞⠀⠀⠀⠐
⠀⠀⠀⠀⠀⠀⠀⠀⡑⠬⢠⠀⠀⠀⠈⠀⠏⠀⠈⢀⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠄⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢘⠀⠀⠀⠈
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⡁⠎⠤⡀⠀⠀⠀⠀⠀⠀⠂⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢐⢢⢒⡡⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⠡⠚⡐⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠡⠀⠁⠀⠠⠁⠀⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    
      ________                __    ____                      
     / ____/ /_  ____  _____/ /_   / __ \___  _________  ____ 
    / / __/ __ \/ __ \/ ___/ __/  / /_/ / _ \/ ___/ __ \/ __ \
   / /_/ / / / / /_/ (__  ) /_   / _, _/  __/ /__/ /_/ / / / /
   \____/_/ /_/\____/____/\__/  /_/ |_|\___/\___/\____/_/ /_/ 
                                                                                                                                                                                                                                                                                      
                                                                                                                                                                              """)
    print(r"              by @ryuug4  ")
    print(f"{NC}")
    print()






def usage():
    print()
    print(f"{GREEN}Usage:{NC} {RED}{sys.argv[0]} -H/--host {NC}<TARGET-IP>{RED} -t/--type {NC}<TYPE>{RED}")
    print(f"{YELLOW}Optional: [-d/--dns {NC}<DNS SERVER>{YELLOW}] [-o/--output {NC}<OUTPUT DIRECTORY>{YELLOW}]{NC}\n")
    print(f"{CYAN}Scan Types:")
    print(f"{CYAN}\tPort    : {NC}Shows all open ports {YELLOW}")
    print(f"{CYAN}\tScript  : {NC}Runs a script scan on found ports {YELLOW}")
    print(f"{CYAN}\tUDP     : {NC}Runs a UDP scan \"requires sudo\" {YELLOW}")
    print(f"{CYAN}\tVulns   : {NC}Runs CVE scan and nmap Vulns scan on all found ports {YELLOW}")
    print(f"{CYAN}\tRecon   : {NC}Suggests recon commands, then prompts to automatically run them")
    print(f"{CYAN}\tAll     : {NC}Runs all the scans {YELLOW}")
    print(f"{NC}")
    sys.exit(1)

def run_command(cmd, shell=True, capture_output=True):
    """Runs a shell command and returns the output string."""
    try:
        result = subprocess.run(cmd, shell=shell, capture_output=capture_output, text=True)
        return result.stdout.strip()
    except Exception as e:
        return ""

def get_system_dns():
    try:
        with open('/etc/resolv.conf', 'r') as f:
            for line in f:
                if line.startswith('nameserver'):
                    return line.split()[1]
    except:
        pass
    return "8.8.8.8"

def check_ping(target):
    """Checks ping and returns the suggested nmap flag and TTL."""
    param = '-c 1 -W 1' if sys.platform.startswith('linux') else '-c 1 -t 1'
    cmd = f"ping {param} {target}"

    output = run_command(cmd)

    if "ttl=" in output.lower():
        # Extract TTL
        match = re.search(r'ttl=(\d+)', output.lower())
        ttl = int(match.group(1)) if match else 0
        return NMAP_PATH, ttl
    else:
        return f"{NMAP_PATH} -Pn", None

def check_os(ttl):
    if ttl is None:
        return "Unknown"
    if 254 <= ttl <= 256: return "OpenBSD/Cisco/Oracle"
    if 127 <= ttl <= 128: return "Windows"
    if 63 <= ttl <= 64: return "Linux"
    return "Some alien stuff!"

def parse_ports_from_nmap(filename, proto="tcp"):
    """Reads nmap file and extracts open ports."""
    ports = []
    if not os.path.exists(filename):
        return ""

    with open(filename, 'r') as f:
        content = f.readlines()

    for line in content:
        # Regex to find ports like 80/tcp open
        if f"/{proto}" in line and "open" in line and "ignored" not in line:
            port = line.split('/')[0].strip()
            if port.isdigit():
                ports.append(port)

    return ",".join(ports)

def progress_bar_logic(scan_type, percent, elapsed, remaining):
    # Simple text based progress bar
    width = 50
    try:
        perc_val = float(percent)
    except:
        perc_val = 0

    filled = int(width * (perc_val / 100))
    bar = "#" * filled + " " * (width - filled)

    sys.stdout.write(f"\033[2AIn progress: {PURPLE}{scan_type}{NC} Scan ({elapsed} elapsed - {remaining} remaining)   \n")
    sys.stdout.write(f"[{bar}] {percent}% done   \n")
    sys.stdout.flush()

def run_nmap_with_progress(cmd, output_file):
    """Runs nmap, redirects to file, and parses the temp file for progress."""

    refresh_rate = 2
    tmp_file = f"{output_file}.tmp"

    # Inject --stats-every if not present (though logic below relies on temp file reading)
    # The logic here replicates the shell script: run command in background, read file.

    full_cmd = f"{cmd} > {tmp_file} 2>&1"

    process = subprocess.Popen(full_cmd, shell=True)

    print("\n") # Space for progress bar

    while process.poll() is None:
        if os.path.exists(tmp_file):
            try:
                # Read last few lines
                lines = run_command(f"tail -n 5 {tmp_file}").split('\n')
                scan_type = "Scanning"
                percent = "0"
                elapsed = "0:00:00"
                remaining = "0:00:00"

                for line in lines:
                    if "undergoing" in line:
                        m = re.search(r"undergoing (.*) Scan", line)
                        if m: scan_type = m.group(1)
                    if "% done" in line:
                        m = re.search(r"About ([\d\.]+).* done", line)
                        if m: percent = m.group(1)
                        m_rem = re.search(r"\((.*) remaining", line)
                        if m_rem: remaining = m_rem.group(1)
                    if "Stats:" in line:
                        m_el = re.search(r"Stats: (.*) elapsed", line)
                        if m_el: elapsed = m_el.group(1)

                progress_bar_logic(scan_type, percent, elapsed, remaining)
            except:
                pass
        time.sleep(refresh_rate)

    # Final cleanup
    sys.stdout.write("\033[0K\r\n\033[0K\r\n") # Clear lines

    # Move temp to final if success, or copy content
    if os.path.exists(tmp_file):
        # Clean up the output for the final file (mimic sed logic)
        # In Python, we'll just copy the tmp to final for simplicity,
        # or read it, filter, and write.
        with open(tmp_file, 'r') as f_in, open(output_file, 'w') as f_out:
            copy = False
            for line in f_in:
                # Simplified logic of the sed command to keep useful info
                if "PORT" in line and "STATE" in line and "SERVICE" in line:
                    copy = True
                if copy:
                    if not line.startswith("SF:") and "service unrecognized" not in line:
                        f_out.write(line)

        # Also print to screen
        with open(output_file, 'r') as f:
            print(f.read())

        os.remove(tmp_file)

def assign_ports(host):
    global ALL_TCP_PORTS, UDP_PORTS
    tcp_file = f"nmap/full_TCP_{host}.nmap"
    if os.path.exists(tcp_file):
        ALL_TCP_PORTS = parse_ports_from_nmap(tcp_file, "tcp")

    udp_file = f"nmap/UDP_{host}.nmap"
    if os.path.exists(udp_file):
        UDP_PORTS = parse_ports_from_nmap(udp_file, "udp")

# --- Scan Functions ---

def port_scan(host, dns_string, nmap_base):
    print(f"{YELLOW}[*] Full TCP port scan launched{NC}")

    # Sudo check logic
    cmd_prefix = ""
    if os.geteuid() != 0:
        print(f"{RED}[!] ALERT{NC}")
        print(f"{RED}>{NC} Nmap needs root for SYN scan. Otherwise it uses Connect scan.")
        choice = input(f"{RED}>{NC} To sudo or not to sudo? y/n \n").lower()
        if choice == 'y':
            subprocess.run("sudo -v", shell=True)
            cmd_prefix = "sudo "

    cmd = f"{cmd_prefix}{nmap_base} -T4 -p- --max-retries 2 -vv --max-scan-delay 30 -Pn --open --stats-every 2s -oN nmap/full_TCP_{host}.nmap {host} {dns_string}"
    run_nmap_with_progress(cmd, f"nmap/full_TCP_{host}.nmap")
    assign_ports(host)

def script_scan(host, dns_string, nmap_base):
    print(f"\n{YELLOW}[*] Script Scan launched on open ports{NC}\n")
    if not ALL_TCP_PORTS:
        print(f"{YELLOW}No ports in port scan.. Skipping!{NC}")
        return

    cmd = f"{nmap_base} -Pn -sCV -p{ALL_TCP_PORTS} --open --stats-every 2s -oN nmap/Script_TCP_{host}.nmap {host} {dns_string}"
    run_nmap_with_progress(cmd, f"nmap/Script_TCP_{host}.nmap")

    # Check if OS detection changed
    script_file = f"nmap/Script_TCP_{host}.nmap"
    if os.path.exists(script_file):
        with open(script_file) as f:
            content = f.read()
            m = re.search(r"Service Info: OS: ([^;]+);", content)
            if m:
                print(f"\n{GREEN}OS Detection modified to: {m.group(1)}{NC}\n")

def udp_scan(host, dns_string, nmap_base):
    print(f"\n{YELLOW}[*] UDP port scan launched{NC}\n")

    cmd_prefix = ""
    if os.geteuid() != 0:
        print(f"{RED}[!] ALERT: UDP requires root.{NC}")
        subprocess.run("sudo -v", shell=True)
        cmd_prefix = "sudo "

    cmd = f"{cmd_prefix}{nmap_base} -sU --max-retries 1 --open --stats-every 2s -oN nmap/UDP_{host}.nmap {host} {dns_string}"
    run_nmap_with_progress(cmd, f"nmap/UDP_{host}.nmap")
    assign_ports(host)

    if UDP_PORTS:
        print(f"\n{YELLOW}Making a script scan on UDP ports: {UDP_PORTS}{NC}\n")
        extra_script = "--script vulners --script-args mincvss=7.0" if os.path.exists("/usr/share/nmap/scripts/vulners.nse") else ""
        cmd = f"sudo nmap -Pn -sCVU {extra_script} -p{UDP_PORTS} --open --stats-every 2s -oN nmap/UDP_Extra_{host}.nmap {host} {dns_string}"
        run_nmap_with_progress(cmd, f"nmap/UDP_Extra_{host}.nmap")
    else:
        print(f"{YELLOW}No UDP ports are open{NC}\n")

def vulns_scan(host, dns_string):
    print(f"\n{YELLOW}[!] Vulnerability Scan{NC}\n")
    ports = ALL_TCP_PORTS

    if os.path.exists("/usr/share/nmap/scripts/vulners.nse"):
        print(f"{YELLOW}> Running CVE scan on ports{NC}\n")
        cmd = f"nmap -sV -Pn --script vulners --script-args mincvss=7.0 -p{ports} --open --stats-every 2s -oN nmap/CVEs_{host}.nmap {host} {dns_string}"
        run_nmap_with_progress(cmd, f"nmap/CVEs_{host}.nmap")
    else:
        print(f"{RED}Skipping CVE scan (vulners.nse missing){NC}")

    print(f"\n{YELLOW}> Running Vuln scan on ports{NC}")
    cmd = f"nmap -sV -Pn --script vuln -p{ports} --open --stats-every 2s -oN nmap/Vulns_{host}.nmap {host} {dns_string}"
    run_nmap_with_progress(cmd, f"nmap/Vulns_{host}.nmap")

def recon_recommend(host, subnet, dns_server, os_type):
    print("\n\n\n")
    print(f"{YELLOW}[*] Recon Recommendations{NC}")
    commands = []

    # Read script scan output
    script_file = f"nmap/Script_TCP_{host}.nmap"
    if not os.path.exists(script_file):
        return commands

    with open(script_file, 'r') as f:
        content = f.read()

    # FTP
    if "ftp" in content:
        port = re.search(r"(\d+)/tcp.*ftp", content)
        p = port.group(1) if port else "21"
        commands.append(f"hydra -s {p} -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt -u -f \"{host}\" ftp | tee \"recon/ftpBruteforce_{host}.txt\"")

    # SMTP
    if "25/tcp" in content:
        commands.append(f"smtp-user-enum -U /usr/share/wordlists/metasploit/unix_users.txt -t \"{host}\" | tee \"recon/smtp_user_enum_{host}.txt\"")

    # DNS
    if "53/tcp" in content and dns_server:
        commands.append(f"host -l \"{host}\" \"{dns_server}\" | tee \"recon/hostname_{host}.txt\"")
        commands.append(f"dnsrecon -r \"{subnet}/24\" -n \"{dns_server}\" | tee \"recon/dnsrecon_{host}.txt\"")

    # HTTP/S
    http_ports = re.findall(r"(\d+)/tcp.*http", content)
    for p in http_ports:
        is_ssl = "ssl/http" in content # Simplified check
        url_proto = "https://" if is_ssl else "http://"

        if is_ssl:
            commands.append(f"sslscan \"{host}\" | tee \"recon/sslscan_{host}_{p}.txt\"")

        commands.append(f"cutycapt --url={url_proto}{host}:{p} --user-agent='incursore' --out=recon/screenshot_{host}_{p}.jpeg")

        if shutil.which("ffuf"):
            commands.append(f"ffuf -ic -w /usr/share/wordlists/dirb/common.txt -u \"{url_proto}{host}:{p}/FUZZ\" | tee \"recon/ffuf_{host}_{p}.txt\"")

        # CMS Checks (simplified regex)
        if "Joomla" in content:
            commands.append(f"joomscan --url \"{host}:{p}\" | tee \"recon/joomscan_{host}_{p}.txt\"")
        if "WordPress" in content:
            commands.append(f"wpscan --url {url_proto}\"{host}:{p}\" --enumerate p | tee \"recon/wpscan_{host}_{p}.txt\"")

    # SMB
    if "445/tcp" in content:
        commands.append(f"smbmap -H \"{host}\" | tee \"recon/smbmap_{host}.txt\"")
        commands.append(f"smbclient -L \"//{host}/\" -U \"guest\"% | tee \"recon/smbclient_{host}.txt\"")
        if "Windows" in os_type:
            commands.append(f"nmap -Pn -p445 --script vuln -oN \"recon/SMB_vulns_{host}.txt\" \"{host}\"")
        elif "Linux" in os_type:
            commands.append(f"enum4linux -a \"{host}\" | tee \"recon/enum4linux_{host}.txt\"")

    return commands

def run_recon(host, commands):
    if not commands:
        print(f"{YELLOW}No Recon Recommendations found...{NC}")
        return

    print(f"{YELLOW}The script will execute the following commands:{NC}")
    for i, cmd in enumerate(commands):
        print(f"{i+1}: {cmd}")

    # Simple interaction
    print(f"\n{YELLOW}Which commands? [All/Skip/Index(e.g. 1,2)]: {NC}", end="")
    # Add timeout logic if strictly needed, but standard input is safer for Python scripts
    try:
        choice = input()
    except:
        choice = "All"

    if choice.lower() in ["", "all"]:
        selected = commands
    elif choice.lower() == "skip":
        return
    else:
        selected = []
        try:
            indices = [int(x.strip()) for x in choice.split(',')]
            for i in indices:
                if 1 <= i <= len(commands):
                    selected.append(commands[i-1])
        except:
            print("Invalid input, skipping.")
            return

    if not os.path.exists("recon"):
        os.makedirs("recon")

    print(f"\n{GREEN}[*] Recon the target{NC}\n")
    for cmd in selected:
        print(f"{YELLOW}[+] Running: {cmd.split()[0]}...{NC}")
        os.system(cmd)
        print(f"{YELLOW}[-] Finished.{NC}\n--------------------------------------")

# --- Main Logic ---

def main():
    parser = argparse.ArgumentParser(description="Python Incursore", add_help=False)
    parser.add_argument("-H", "--host", required=True, help="Target IP/Host")
    parser.add_argument("-t", "--type", required=True, help="Scan Type: Port, Script, UDP, Vulns, Recon, All")
    parser.add_argument("-d", "--dns", help="Custom DNS")
    parser.add_argument("-o", "--output", help="Output Directory")

    if len(sys.argv) == 1:
        usage()

    args = parser.parse_args()

    host = args.host
    scan_type = args.type.capitalize()

    if not NMAP_PATH:
        print(f"{RED}Nmap not installed. Eject!{NC}")
        sys.exit(1)

    # Setup Directories
    out_dir = args.output if args.output else host
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)
    os.chdir(out_dir)
    if not os.path.exists("nmap"):
        os.makedirs("nmap")

    # DNS Setup
    dns_server = args.dns if args.dns else get_system_dns()
    dns_string = f"--dns-server={dns_server}" if args.dns else "--system-dns"

    # Header Info
    print_banner()
    print(f"{GREEN}Launching a {scan_type} scan on {NC}{host}")

    # Resolve IP
    try:
        target_ip = socket.gethostbyname(host)
        print(f"{YELLOW} with IP {NC}{target_ip}\n")
    except:
        target_ip = host
        print(f"{RED}Could not resolve IP.{NC}\n")

    # Subnet calculation (simple)
    subnet = ".".join(target_ip.split('.')[:3]) + ".0"

    # Ping & OS
    nmap_base, ttl = check_ping(target_ip)
    os_detected = check_os(ttl)
    if ttl:
        print(f"{GREEN}Host is likely running {NC}{PURPLE}{os_detected}{NC}\n")
    else:
        print(f"{YELLOW}No ping detected.. Will not use ping scans!{NC}\n")

    # Logic Router
    if scan_type == "Port":
        port_scan(host, dns_string, nmap_base)
    elif scan_type == "Script":
        if not os.path.exists(f"nmap/full_TCP_{host}.nmap"):
            port_scan(host, dns_string, nmap_base)
        else:
            assign_ports(host)
        script_scan(host, dns_string, nmap_base)
    elif scan_type == "Udp":
        udp_scan(host, dns_string, nmap_base)
    elif scan_type == "Vulns":
        if not os.path.exists(f"nmap/full_TCP_{host}.nmap"):
            port_scan(host, dns_string, nmap_base)
        else:
            assign_ports(host)
        vulns_scan(host, dns_string)
    elif scan_type == "Recon":
        # Ensure dependencies exist
        if not os.path.exists(f"nmap/Script_TCP_{host}.nmap"):
            if not os.path.exists(f"nmap/full_TCP_{host}.nmap"):
                port_scan(host, dns_string, nmap_base)
            script_scan(host, dns_string, nmap_base)
        else:
            assign_ports(host)

        cmds = recon_recommend(host, subnet, dns_server, os_detected)
        run_recon(host, cmds)

    elif scan_type == "All":
        port_scan(host, dns_string, nmap_base)
        script_scan(host, dns_string, nmap_base)
        udp_scan(host, dns_string, nmap_base)
        vulns_scan(host, dns_string)
        cmds = recon_recommend(host, subnet, dns_server, os_detected)
        run_recon(host, cmds)
    else:
        print(f"{RED}Invalid Type!{NC}")
        usage()

    # Footer
    print(f"\n{GREEN}[!] Finished all scans{NC}\n")
    elapsed = time.time() - START_TIME
    m, s = divmod(elapsed, 60)
    h, m = divmod(m, 60)
    print(f"{YELLOW}Completed in {int(h)}h {int(m)}m {int(s)}s{NC}")

if __name__ == "__main__":
    main()
