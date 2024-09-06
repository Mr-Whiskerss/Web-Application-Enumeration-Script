
#!/usr/bin/python3

import os
import subprocess
import sys
from colorama import Fore, Style, init
from tqdm import tqdm
import re

# Initialize colorama for color support. This helps visuals when running the script.
init(autoreset=True)

# Helper function.
def run_command(command, output_file):
    try:
        print(f"{Fore.YELLOW}Running: {command}")
        with open(output_file, 'a') as f:
            f.write(f"Running command: {command}\n")
            result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            f.write(result.stdout + result.stderr)
            if result.returncode == 0:
                print(f"{Fore.GREEN}Success: {command}")
            else:
                print(f"{Fore.RED}Error: {command}. Check output file for details.")
                f.write(f"Error running command: {command}. Exit code: {result.returncode}\n")
    except Exception as e:
        print(f"{Fore.RED}An error occurred while running the command '{command}': {e}")

# Function to check if the input is a valid domain name or IP address.
def validate_input(user_input):
    # Regular expression to check if it's a valid IP address (IPv4)
    ip_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    # Simple pattern for domain validation (not exhaustive)
    domain_pattern = r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
    
    if re.match(ip_pattern, user_input):
        return 'ip'
    elif re.match(domain_pattern, user_input):
        return 'domain'
    else:
        return None

# Helper function to prompt for user input and validate
def prompt_input(message):
    user_input = input(f"{Fore.CYAN}{message}")
    if not user_input.strip():
        print(f"{Fore.RED}Input cannot be empty. Please provide a valid input.")
        sys.exit(1)
    
    input_type = validate_input(user_input)
    
    if input_type is None:
        print(f"{Fore.RED}Invalid input. Please provide a valid IP address or domain name.")
        sys.exit(1)
    
    return user_input, input_type

# Function to prompt for y/n input
def prompt_yes_no(message):
    while True:
        user_input = input(f"{Fore.CYAN}{message} (y/n): ").strip().lower()
        if user_input in ['y', 'n']:
            return user_input
        else:
            print(f"{Fore.RED}Invalid input. Please enter 'y' or 'n'.")


# Check if a command exists. Checking if tools exsit please ensure all tools are installed as recommended within the readme.
def command_exists(command):
    return subprocess.call(f"type {command}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0

# Output file
output_file = "web_recon_output.md"
try:
    with open(output_file, 'w') as f:
        f.write("==================================\n")
        f.write("Web Recon Tool\n")
        f.write("==================================\n")
    print(f"{Fore.MAGENTA}Output file initialized: {output_file}")
except Exception as e:
    print(f"{Fore.RED}Error creating output file: {e}")
    sys.exit(1)

# Prompt user for URL or IP address. 
try:
    target, target_type = prompt_input("Enter URL or IP address to be tested: ")
    print(f"{Fore.GREEN}Target Entered: {target} ({target_type})")
except ValueError as e:
    print(e)
    sys.exit(1)

with open(output_file, 'a') as f:
    f.write(f"Target Entered: {target}\n")

# Setup progress bar. This is to ensure you can see what step the tool is at.
steps = 9
progress_bar = tqdm(total=steps, desc=f"{Fore.CYAN}Progress", ncols=100)

# Passive Information Gathering
try:
    print(f"{Fore.BLUE}\nPerforming Passive Information Gathering\n{'='*40}")
    with open(output_file, 'a') as f:
        f.write("==================================\n")
        f.write("Performing Passive information gathering Stage\n")
        f.write("==================================\n")

    run_command(f"nslookup {target}", output_file)
    if target_type == 'domain':
        run_command(f"dnsrecon -d {target}", output_file)
    progress_bar.update(1)
except Exception as e:
    print(f"{Fore.RED}Error during passive information gathering: {e}")

# Active Information Gathering
try:
    print(f"{Fore.BLUE}\nPerforming Active Information Gathering\n{'='*40}")
    with open(output_file, 'a') as f:
        f.write("==================================\n")
        f.write("Performing Active information gathering Stage\n")
        f.write("==================================\n")

    run_command(f"nmap -vv -n -sV -Pn -O -oA full_tcp -p- {target}", output_file)
    progress_bar.update(1)
except Exception as e:
    print(f"{Fore.RED}Error during active information gathering: {e}")

# HTTP Methods Check
try:
    input_check = prompt_yes_no("Check for allowed HTTP methods? (y/n): ").lower()
    if input_check == 'y':
        print(f"{Fore.BLUE}Checking for HTTP methods...\n{'='*40}")
        if command_exists("nmap"):
            run_command(f"nmap --script=http-methods.nse {target}", output_file)
        else:
            print(f"{Fore.RED}Error: Nmap is not installed.")
            sys.exit(1)
    else:
        print(f"{Fore.YELLOW}Skipping HTTP methods check.")
        with open(output_file, 'a') as f:
            f.write("HTTP methods check skipped.\n")
    progress_bar.update(1)
except Exception as e:
    print(f"{Fore.RED}Error during HTTP methods check: {e}")

# WhatWeb and Robots.txt Lookup (only for domain names)
if target_type == 'domain':
    try:
        print(f"{Fore.BLUE}\nPerforming WhatWeb and Robots.txt Lookup\n{'='*40}")
        run_command(f"whatweb -v -a 3 {target} | tee what_web_output_web_Recon.txt", output_file)
        progress_bar.update(1)
        run_command(f"curl {target}/robots.txt | tee curl_robots_web_Recon.txt", output_file)
        progress_bar.update(1)
        run_command(f"curl https://{target}/robots.txt | tee curl_robots_https_web_Recon.txt", output_file)
        progress_bar.update(1)
    except Exception as e:
        print(f"{Fore.RED}Error during WhatWeb and robots.txt lookup: {e}")

# Vulnerability Scan
try:
    input_check = prompt_yes_no("Perform Vulnerability Scan? (y/n): ").lower()
    if input_check == 'y':
        print(f"{Fore.BLUE}Performing Vulnerability Scan...\n{'='*40}")
        if command_exists("nikto"):
            run_command(f"nikto -h -c https://{target} | tee nikto_output.txt", output_file)
        else:
            print(f"{Fore.RED}Error: Nikto is not installed.")
            sys.exit(1)
    else:
        print(f"{Fore.YELLOW}Skipping Vulnerability Scan.")
        with open(output_file, 'a') as f:
            f.write("Vulnerability scan skipped.\n")
    progress_bar.update(1)
except Exception as e:
    print(f"{Fore.RED}Error during vulnerability scan: {e}")

# SSL/TLS Scan
try:
    print(f"{Fore.BLUE}Performing SSL/TLS Scan...\n{'='*40}")
    run_command(f"sslscan https://{target} | tee ssl_Scan_output.txt", output_file)
    progress_bar.update(1)
except Exception as e:
    print(f"{Fore.RED}Error during SSL/TLS scan: {e}")

# Script End
with open(output_file, 'a') as f:
    f.write("==================================\n")
    f.write("Script End\n")
    f.write("==================================\n")

progress_bar.close()
print(f"{Fore.MAGENTA}\nAll tasks completed! Check the output file for full details of tool output.\n")
