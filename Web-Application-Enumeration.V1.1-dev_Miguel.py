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
    ip_pattern = r"^(?:((25[0-4])|(2[0-4][0-9])|(1?[0-9]{1,2}))\.){3}(?:(25[0-4])|(2[0-4][0-9])|(1[0-9]{1,2})|([1-9][0-9]?))$"
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

# Function to prompt for files or directories
def prompt_file(message):
    # Simple pattern for a file path (UNIX notation, white spaces can be added by using "\ ")
    file_pattern = r"^(?:(\/|(\.{1,2}\/)*)?(\.?([a-zA-Z0-9\-_]|(\\ )))+)+$"

    user_input = input(f"{Fore.CYAN}{message}")
    if not user_input.strip():
        print(f"{Fore.RED}Input cannot be empty. Please provide a valid input.")
        sys.exit(1)
    if re.match(file_pattern, user_input):
        return user_input, 'file'
    else:
        # Unlike the original IP or domain input, this one is meant to be used for retries (Inside a loop)
        return user_input, None

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

###########################
# TO-DO:
###########################
#
# Support for custom ports
# Custom output file
# Set some command-line arguments so you don't have to use an interactive UI for everything: setting target url and port, output file, stealthier modes for nikto, nmap and gobuster (alternative commands, TBD)
###########################
# port = None
# i = 1
# while i<len(sys.argv):
#     arg = sys.argv[i]
#     if arg == '-p' || arg == '--port':
#
#         port = sys.argv[i+1]
#         i += 1
#
#     print(f"Argument {i:>6}: {arg}")
#     i += 1
port = None
target = None
arg = None
argc = len(sys.argv)
i = 1
try:
    while i<argc:
        arg = sys.argv[i]
        if arg == '-p' or arg == '--port':
            i += 1
            port = int(sys.argv[i])
            if port < 1:
                raise ValueError("Invalid port value: " + sys.argv[i])
        elif arg == '-o' or arg == '--output':
            i += 1
            output_file = sys.argv[i]
            # If the name of the file starts with - we'll asume the user forgot to set this parameter's value
            if output_file[0] == '-':
                raise ValueError("")
        elif arg == '-h' or arg == '--help':
            print('Usage: python ' + sys.argv[0] + '[-h|--help] [-p|--port=PORT] [-o|--output=OUTPUT_FILE] <target>')
            print('[-h|--help] : Display this help message.')
            print('[-p|--port=PORT] : Set the port number.')
            print('[-o|--output=OUTPUT_FILE] : Use a custom output file. Defaults to web_recon_output.md')
            print('<target> : Set the target domain/IP address. If not set, the user will be asked to set it.')
            # if argc == 2:
            #     sys.exit(0)
        else:
            target = arg
        # print(f"Argument {i:>6}: {arg}")
        i += 1
except Exception as e:
    if arg == '-p' or arg == '--port':
        if isinstance(e, ValueError):
            print(f"{Fore.RED}{e}")
        else:
            print(f"{Fore.RED}Missing argument: port")
    elif arg == '-o' or arg == '--output':
        print(f"{Fore.RED}Missing argument: output file")
    else:
        print(f"{Fore.RED}Missing arguments!")
    sys.exit(1)

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
    if not target:
        target, target_type = prompt_input("Enter URL or IP address to be tested: ")
    else:
        target_type = validate_input(target)
    print(f"{Fore.GREEN}Target Entered: {target} ({target_type})")
except ValueError as e:
    print(e)
    sys.exit(1)

with open(output_file, 'a') as f:
    f.write(f"Target Entered: {target}\n")

# Setup progress bar. This is to ensure you can see what step the tool is at.
steps = 9   # Update if we keep adding steps
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

    run_command(f"sudo nmap -vv -n -sV -Pn -O -oA full_tcp -p- {target}", output_file) # We should consider the usefulness of TCP scans on Web assessments
    progress_bar.update(1)
except Exception as e:
    print(f"{Fore.RED}Error during active information gathering: {e}")

# HTTP Methods Check
try:
    input_check = prompt_yes_no("Check for allowed HTTP methods?").lower()
    if input_check == 'y':
        print(f"{Fore.BLUE}Checking for HTTP methods...\n{'='*40}")
        if command_exists("nmap"):
            if (port is None):
                run_command(f"nmap --script=http-methods.nse {target}", output_file)
            else:
                run_command(f"nmap --script=http-methods.nse -p {port} {target}", output_file)
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
        full_target = target if port is None else (target + ":" + str(port))
        run_command(f"whatweb -v -a 3 {full_target} | tee what_web_output_web_Recon.txt", output_file)  # The command will always try to use HTTP unless we append https:// to the target
        progress_bar.update(1)
        run_command(f"curl {full_target}/robots.txt | tee curl_robots_web_Recon.txt", output_file)
        progress_bar.update(1)
        run_command(f"curl https://{full_target}/robots.txt | tee curl_robots_https_web_Recon.txt", output_file)
        progress_bar.update(1)
    except Exception as e:
        print(f"{Fore.RED}Error during WhatWeb and robots.txt lookup: {e}")

# Directory and File Enumeration
try:
    input_check = prompt_yes_no("Perform Dir enumeration?").lower()
    if input_check == 'y':
        input_check = prompt_yes_no("Do you want to use a custom wordlist?").lower()
        wordlist = '/usr/share/seclists/Discovery/Web-Content/big.txt'
        pattern = 'file'
        if input_check == 'y':
            while True:
                wordlist, pattern = prompt_file("Insert path of the wordlist: ")
                wordlist_found = os.path.isfile(wordlist)
                # TECHNICALLY SPEAKING there are file names that can match an IP addresses or domain names
                if pattern and wordlist_found:
                    print(f"{Fore.GREEN} {wordlist}: The file exists!")
                    break
                elif not pattern:
                    print(f"{Fore.RED} {wordlist}: Invalid file name! Make sure to use UNIX-style paths with escaped whitespaces.")
                else:
                    print(f"{Fore.RED} {wordlist}: File not found!")


        print(f"{Fore.BLUE}Searching for common directories and files...\n{'='*20}")
        if command_exists("gobuster"):
            if port is None:
                run_command(f"gobuster dir -w {wordlist} --timeout 5s --delay 200ms -kqra 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36' -u https://{target} -o gobuster_dir_enumeration_Recon.txt", output_file)
            else:
                run_command(f"gobuster dir -w {wordlist} --timeout 5s --delay 200ms -kqra 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36' -u https://{target}:{str(port)} -o gobuster_dir_enumeration_Recon.txt", output_file)
        else:
            print(f"{Fore.YELLOW}Warning: Gobuster is not installed. Trying to use Dirbuster instead.")
            if command_exists("dirbuster"):
                with open(output_file, 'a') as f:
                    f.write("Gobuster not installed. Performing directory enumeration with Dirbuster.\n")
                if port is None:
                    run_command(f"dirbuster -H -l {wordlist} -t 5 -v -u https://{target} -r dirbuster_dir_enumeration_Recon.txt", output_file)
                else:
                    run_command(f"dirbuster -H -l {wordlist} -t 5 -v -u https://{target}:{str(port)} -r dirbuster_dir_enumeration_Recon.txt", output_file)
            else:
                print(f"{Fore.RED}Error: Gobuster and Dirbuster not installed.")
                sys.exit(1)
    else:
        print(f"{Fore.YELLOW}Skipping directory enumeration.")
        with open(output_file, 'a') as f:
            f.write("Directory enumeration skipped.\n")
    progress_bar.update(1)
except Exception as e:
    print(f"{Fore.RED}Error during directory enumeration: {e}")

# Vulnerability Scan
try:
    input_check = prompt_yes_no("Perform Vulnerability Scan?").lower()
    if input_check == 'y':
        print(f"{Fore.BLUE}Performing Vulnerability Scan...\n{'='*40}")
        if command_exists("nikto"):
            if port is None:
                run_command(f"nikto -h -c https://{target} | tee nikto_output.txt", output_file)
            else:
                run_command(f"nikto -h -c -p {str(port)} https://{target} | tee nikto_output.txt", output_file)
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
    print(f"\n{Fore.BLUE}Performing SSL/TLS Scan...\n{'='*40}")
    if port is None:
        run_command(f"sslscan https://{target} | tee ssl_Scan_output.txt", output_file)
    else:
        run_command(f"sslscan https://{target}:{str(port)} | tee ssl_Scan_output.txt", output_file)
    progress_bar.update(1)
    progress_bar.close()
except Exception as e:
    print(f"{Fore.RED}Error during SSL/TLS scan: {e}")

# Script End
with open(output_file, 'a') as f:
    f.write("==================================\n")
    f.write("Script End\n")
    f.write("==================================\n")

# progress_bar.close()
print(f"{Fore.MAGENTA}\nAll tasks completed! Check the output file for full details of tool output.\n")
