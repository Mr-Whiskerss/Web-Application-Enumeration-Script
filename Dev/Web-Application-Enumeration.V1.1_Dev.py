#!/usr/bin/env python3

import os
import re
import sys
import subprocess
from enum import Enum
from argparse import ArgumentParser
from colorama import Fore, Style, init
from tqdm import tqdm

# Initialize colorama
init(autoreset=True)

# === Configuration ===
OUTPUT_FILE = "web_recon_output.md"
PROGRESS_STEPS = 9

class TargetType(Enum):
    IP = "ip"
    DOMAIN = "domain"

# === Helper Functions ===
def log_output(message, file=OUTPUT_FILE):
    with open(file, 'a') as f:
        f.write(message + '\n')

def run_command(command, desc, output_file=OUTPUT_FILE):
    print(f"{Fore.YELLOW}Running: {desc}")
    log_output(f"Running command: {command}")
    try:
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        log_output(result.stdout)
        log_output(result.stderr)
        if result.returncode == 0:
            print(f"{Fore.GREEN}Success: {desc}")
        else:
            print(f"{Fore.RED}Failed: {desc}")
            log_output(f"ERROR: {desc} failed with code {result.returncode}")
    except Exception as e:
        print(f"{Fore.RED}Exception running {desc}: {e}")
        log_output(f"EXCEPTION: {e}")

def validate_target(user_input):
    ip_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    domain_pattern = r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"

    if re.match(ip_pattern, user_input):
        return TargetType.IP
    elif re.match(domain_pattern, user_input):
        return TargetType.DOMAIN
    else:
        return None

def prompt_user(prompt_text):
    return input(f"{Fore.CYAN}{prompt_text}").strip()

def yes_no(prompt_text):
    while True:
        answer = input(f"{Fore.CYAN}{prompt_text} (y/n): ").lower()
        if answer in ('y', 'n'):
            return answer == 'y'
        else:
            print(f"{Fore.RED}Please enter 'y' or 'n'.")

def command_exists(command):
    return subprocess.call(f"type {command}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0

# === Recon Functions ===
def passive_info_gathering(target, target_type, progress_bar):
    print(f"{Fore.BLUE}\nPerforming Passive Information Gathering\n{'='*40}")
    log_output("=== Passive Information Gathering ===")

    run_command(f"nslookup {target}", "NSLookup", OUTPUT_FILE)
    if target_type == TargetType.DOMAIN:
        run_command(f"dnsrecon -d {target}", "DNSRecon", OUTPUT_FILE)
    progress_bar.update(1)

def active_info_gathering(target, progress_bar):
    print(f"{Fore.BLUE}\nPerforming Active Information Gathering\n{'='*40}")
    log_output("=== Active Information Gathering ===")

    run_command(f"nmap -vv -n -sV -Pn -O -oA full_tcp -p 80,443,8080 {target}", "Nmap TCP Scan", OUTPUT_FILE)
    progress_bar.update(1)

def http_methods_check(target, progress_bar):
    if yes_no("Check for allowed HTTP methods?"):
        print(f"{Fore.BLUE}Checking for HTTP methods...\n{'='*40}")
        if command_exists("nmap"):
            run_command(f"nmap --script=http-methods.nse {target}", "HTTP Methods Check", OUTPUT_FILE)
        else:
            print(f"{Fore.RED}Nmap is not installed.")
            sys.exit(1)
    else:
        print(f"{Fore.YELLOW}Skipping HTTP methods check.")
        log_output("HTTP methods check skipped.")
    progress_bar.update(1)

def whatweb_and_robots(target, target_type, progress_bar):
    if target_type == TargetType.DOMAIN:
        print(f"{Fore.BLUE}\nPerforming WhatWeb and Robots.txt Lookup\n{'='*40}")
        run_command(f"whatweb -v -a 3 {target}", "WhatWeb Scan", OUTPUT_FILE)
        progress_bar.update(1)

        run_command(f"curl {target}/robots.txt", "Robots.txt (HTTP)", OUTPUT_FILE)
        progress_bar.update(1)

        run_command(f"curl https://{target}/robots.txt", "Robots.txt (HTTPS)", OUTPUT_FILE)
        progress_bar.update(1)

def vulnerability_scan(target, progress_bar):
    if yes_no("Perform Vulnerability Scan?"):
        print(f"{Fore.BLUE}Performing Vulnerability Scan...\n{'='*40}")
        if command_exists("nikto"):
            run_command(f"nikto -h https://{target}", "Nikto Vulnerability Scan", OUTPUT_FILE)
        else:
            print(f"{Fore.RED}Nikto is not installed.")
            sys.exit(1)
    else:
        print(f"{Fore.YELLOW}Skipping Vulnerability Scan.")
        log_output("Vulnerability scan skipped.")
    progress_bar.update(1)

def ssl_tls_scan(target, progress_bar):
    print(f"{Fore.BLUE}Performing SSL/TLS Scan...\n{'='*40}")
    run_command(f"sslscan https://{target}", "SSL/TLS Scan", OUTPUT_FILE)
    progress_bar.update(1)

# === Main Logic ===
def main():
    parser = ArgumentParser(description="Web Reconnaissance Tool")
    parser.add_argument("--target", help="Target domain or IP address", required=False)
    parser.add_argument("--auto", help="Run without prompts", action="store_true")
    args = parser.parse_args()

    # Initialize output file
    with open(OUTPUT_FILE, 'w') as f:
        f.write("==================================\n")
        f.write("Web Recon Tool\n")
        f.write("==================================\n")

    if args.target:
        target_input = args.target
    else:
        target_input = prompt_user("Enter URL or IP address to be tested: ")

    target_type = validate_target(target_input)

    if not target_type:
        print(f"{Fore.RED}Invalid target. Exiting.")
        sys.exit(1)

    log_output(f"Target Entered: {target_input}")

    progress_bar = tqdm(total=PROGRESS_STEPS, desc=f"{Fore.CYAN}Progress", ncols=100)

    try:
        passive_info_gathering(target_input, target_type, progress_bar)
        active_info_gathering(target_input, progress_bar)
        http_methods_check(target_input, progress_bar)
        whatweb_and_robots(target_input, target_type, progress_bar)
        vulnerability_scan(target_input, progress_bar)
        ssl_tls_scan(target_input, progress_bar)
    except Exception as e:
        print(f"{Fore.RED}Fatal error: {e}")
        sys.exit(1)

    log_output("=== Script End ===")
    progress_bar.close()

    print(f"{Fore.MAGENTA}\nAll tasks completed! Check the output file '{OUTPUT_FILE}' for full details.\n")

if __name__ == "__main__":
    main()
