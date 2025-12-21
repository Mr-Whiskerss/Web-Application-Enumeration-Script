#!/usr/bin/env python3

import os
import re
import sys
import subprocess
import shutil
from enum import Enum
from argparse import ArgumentParser
from colorama import Fore, Style, init
from tqdm import tqdm

# Initialize colorama
init(autoreset=True)

# === Configuration ===
OUTPUT_FILE = "web_recon_output.md"
PROGRESS_STEPS = 13

class TargetType(Enum):
    IP = "ip"
    DOMAIN = "domain"

# === Tool Definitions ===
# Each tool has: name, check_command, install_commands (by package manager)
REQUIRED_TOOLS = {
    "nslookup": {
        "check": "nslookup",
        "description": "DNS lookup utility",
        "install": {
            "apt": "sudo apt install -y dnsutils",
            "dnf": "sudo dnf install -y bind-utils",
            "yum": "sudo yum install -y bind-utils",
            "pacman": "sudo pacman -S --noconfirm bind",
            "brew": "brew install bind"
        }
    },
    "dnsrecon": {
        "check": "dnsrecon",
        "description": "DNS enumeration tool",
        "install": {
            "apt": "sudo apt install -y dnsrecon",
            "dnf": "sudo dnf install -y dnsrecon",
            "pip": "pip install dnsrecon",
            "brew": "brew install dnsrecon"
        }
    },
    "nmap": {
        "check": "nmap",
        "description": "Network scanner",
        "install": {
            "apt": "sudo apt install -y nmap",
            "dnf": "sudo dnf install -y nmap",
            "yum": "sudo yum install -y nmap",
            "pacman": "sudo pacman -S --noconfirm nmap",
            "brew": "brew install nmap"
        }
    },
    "whatweb": {
        "check": "whatweb",
        "description": "Web technology identifier",
        "install": {
            "apt": "sudo apt install -y whatweb",
            "dnf": "sudo dnf install -y whatweb",
            "gem": "sudo gem install whatweb",
            "brew": "brew install whatweb"
        }
    },
    "curl": {
        "check": "curl",
        "description": "URL transfer tool",
        "install": {
            "apt": "sudo apt install -y curl",
            "dnf": "sudo dnf install -y curl",
            "yum": "sudo yum install -y curl",
            "pacman": "sudo pacman -S --noconfirm curl",
            "brew": "brew install curl"
        }
    },
    "nikto": {
        "check": "nikto",
        "description": "Web vulnerability scanner",
        "install": {
            "apt": "sudo apt install -y nikto",
            "dnf": "sudo dnf install -y nikto",
            "pacman": "sudo pacman -S --noconfirm nikto",
            "brew": "brew install nikto"
        }
    },
    "testssl": {
        "check": "testssl",
        "description": "SSL/TLS testing tool",
        "install": {
            "apt": "sudo apt install -y testssl.sh",
            "dnf": "sudo dnf install -y testssl",
            "pacman": "sudo pacman -S --noconfirm testssl.sh",
            "brew": "brew install testssl",
            "git": "git clone --depth 1 https://github.com/drwetter/testssl.sh.git && sudo ln -s $(pwd)/testssl.sh/testssl.sh /usr/local/bin/testssl"
        }
    },
    "ffuf": {
        "check": "ffuf",
        "description": "Fast web fuzzer for content discovery",
        "install": {
            "apt": "sudo apt install -y ffuf",
            "go": "go install github.com/ffuf/ffuf/v2@latest",
            "brew": "brew install ffuf"
        }
    },
    "subfinder": {
        "check": "subfinder",
        "description": "Subdomain discovery tool",
        "install": {
            "apt": "sudo apt install -y subfinder",
            "go": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "brew": "brew install subfinder"
        }
    },
    "wappalyzer": {
        "check": "wappalyzer",
        "description": "Technology profiler for websites",
        "install": {
            "npm": "sudo npm install -g wappalyzer",
            "yarn": "yarn global add wappalyzer"
        }
    }
}

# === Helper Functions ===
def log_output(message, file=OUTPUT_FILE):
    with open(file, 'a') as f:
        f.write(message + '\n')

def run_command(command, desc, output_file=OUTPUT_FILE, timeout=300):
    print(f"{Fore.YELLOW}Running: {desc}")
    log_output(f"\n{'='*60}")
    log_output(f"Running command: {command}")
    log_output(f"{'='*60}")
    try:
        result = subprocess.run(
            command, 
            shell=True, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True,
            timeout=timeout
        )
        log_output(result.stdout)
        if result.stderr:
            log_output(f"STDERR: {result.stderr}")
        if result.returncode == 0:
            print(f"{Fore.GREEN}Success: {desc}")
        else:
            print(f"{Fore.RED}Failed: {desc}")
            log_output(f"ERROR: {desc} failed with code {result.returncode}")
    except subprocess.TimeoutExpired:
        print(f"{Fore.RED}Timeout: {desc} (exceeded {timeout}s)")
        log_output(f"TIMEOUT: {desc} exceeded {timeout} seconds")
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
    """Check if a command exists in PATH"""
    return shutil.which(command) is not None

def is_root():
    """Check if script is running as root"""
    return os.geteuid() == 0

def get_sudo_prefix():
    """Return 'sudo ' if not running as root, otherwise empty string"""
    return "" if is_root() else "sudo "

def detect_package_manager():
    """Detect the available package manager on the system"""
    managers = [
        ("apt", "apt"),
        ("dnf", "dnf"),
        ("yum", "yum"),
        ("pacman", "pacman"),
        ("brew", "brew"),
        ("go", "go"),
        ("npm", "npm"),
        ("yarn", "yarn"),
        ("pip", "pip3"),
        ("pip", "pip"),
        ("gem", "gem"),
        ("git", "git")
    ]
    
    available = []
    for name, cmd in managers:
        if command_exists(cmd):
            available.append(name)
    
    return available

def check_tool(tool_name):
    """Check if a specific tool is installed"""
    tool_info = REQUIRED_TOOLS.get(tool_name)
    if not tool_info:
        return True  # Unknown tool, assume available
    
    return command_exists(tool_info["check"])

def get_install_command(tool_name, available_managers):
    """Get the install command for a tool based on available package managers"""
    tool_info = REQUIRED_TOOLS.get(tool_name)
    if not tool_info:
        return None
    
    # Priority order for package managers
    priority = ["apt", "dnf", "yum", "pacman", "brew", "go", "npm", "yarn", "pip", "gem", "git"]
    
    for manager in priority:
        if manager in available_managers and manager in tool_info["install"]:
            return tool_info["install"][manager]
    
    return None

def install_tool(tool_name, install_cmd):
    """Attempt to install a tool"""
    print(f"{Fore.YELLOW}Installing {tool_name}...")
    try:
        result = subprocess.run(install_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            print(f"{Fore.GREEN}Successfully installed {tool_name}")
            return True
        else:
            print(f"{Fore.RED}Failed to install {tool_name}")
            print(f"{Fore.RED}Error: {result.stderr}")
            return False
    except Exception as e:
        print(f"{Fore.RED}Exception installing {tool_name}: {e}")
        return False

def check_all_tools():
    """Check all required tools and offer to install missing ones"""
    print(f"{Fore.BLUE}\n{'='*50}")
    print(f"{Fore.BLUE}Checking Required Tools")
    print(f"{Fore.BLUE}{'='*50}\n")
    
    missing_tools = []
    installed_tools = []
    
    for tool_name, tool_info in REQUIRED_TOOLS.items():
        if check_tool(tool_name):
            installed_tools.append(tool_name)
            print(f"{Fore.GREEN}[✓] {tool_name} - {tool_info['description']}")
        else:
            missing_tools.append(tool_name)
            print(f"{Fore.RED}[✗] {tool_name} - {tool_info['description']}")
    
    print()
    
    if not missing_tools:
        print(f"{Fore.GREEN}All required tools are installed!\n")
        return True
    
    print(f"{Fore.YELLOW}Missing tools: {', '.join(missing_tools)}\n")
    
    # Detect available package managers
    available_managers = detect_package_manager()
    if not available_managers:
        print(f"{Fore.RED}No supported package manager found.")
        print(f"{Fore.YELLOW}Please install the missing tools manually:")
        for tool in missing_tools:
            print(f"  - {tool}")
        return False
    
    print(f"{Fore.CYAN}Detected package managers: {', '.join(available_managers)}\n")
    
    # Offer to install missing tools
    if yes_no("Would you like to install the missing tools?"):
        failed_installs = []
        
        for tool_name in missing_tools:
            install_cmd = get_install_command(tool_name, available_managers)
            
            if install_cmd:
                print(f"\n{Fore.CYAN}Install command: {install_cmd}")
                if yes_no(f"Install {tool_name}?"):
                    if not install_tool(tool_name, install_cmd):
                        failed_installs.append(tool_name)
                else:
                    print(f"{Fore.YELLOW}Skipping {tool_name}")
                    failed_installs.append(tool_name)
            else:
                print(f"{Fore.RED}No install command available for {tool_name}")
                print(f"{Fore.YELLOW}Available install options:")
                for manager, cmd in REQUIRED_TOOLS[tool_name]["install"].items():
                    print(f"  {manager}: {cmd}")
                failed_installs.append(tool_name)
        
        if failed_installs:
            print(f"\n{Fore.YELLOW}Warning: The following tools were not installed: {', '.join(failed_installs)}")
            print(f"{Fore.YELLOW}Some scans may fail or be skipped.")
            if not yes_no("Continue anyway?"):
                return False
    else:
        print(f"\n{Fore.YELLOW}Skipping tool installation.")
        print(f"{Fore.YELLOW}Some scans may fail or be skipped.")
        if not yes_no("Continue anyway?"):
            return False
    
    return True

def check_tool_before_scan(tool_name, scan_name):
    """Check if a tool is available before running a scan"""
    if not check_tool(tool_name):
        print(f"{Fore.RED}{tool_name} is not installed. Skipping {scan_name}.")
        log_output(f"{scan_name} skipped - {tool_name} not installed.")
        return False
    return True

# === Recon Functions ===
def passive_info_gathering(target, target_type, progress_bar):
    print(f"{Fore.BLUE}\n{'='*50}")
    print(f"{Fore.BLUE}Passive Information Gathering")
    print(f"{Fore.BLUE}{'='*50}")
    log_output("\n# Passive Information Gathering")

    if check_tool_before_scan("nslookup", "NSLookup"):
        run_command(f"nslookup {target}", "NSLookup", OUTPUT_FILE)
    
    if target_type == TargetType.DOMAIN:
        if check_tool_before_scan("dnsrecon", "DNSRecon"):
            run_command(f"dnsrecon -d {target}", "DNSRecon", OUTPUT_FILE)
    progress_bar.update(1)

def subdomain_enumeration(target, target_type, progress_bar):
    """Subdomain enumeration using subfinder"""
    if target_type != TargetType.DOMAIN:
        print(f"{Fore.YELLOW}Skipping subdomain enumeration (target is IP)")
        log_output("Subdomain enumeration skipped - target is IP address")
        progress_bar.update(1)
        return
    
    print(f"{Fore.BLUE}\n{'='*50}")
    print(f"{Fore.BLUE}Subdomain Enumeration")
    print(f"{Fore.BLUE}{'='*50}")
    log_output("\n# Subdomain Enumeration")
    
    if check_tool_before_scan("subfinder", "Subfinder"):
        run_command(
            f"subfinder -d {target} -silent", 
            "Subfinder Subdomain Enumeration", 
            OUTPUT_FILE,
            timeout=120
        )
    progress_bar.update(1)

def active_info_gathering(target, progress_bar):
    print(f"{Fore.BLUE}\n{'='*50}")
    print(f"{Fore.BLUE}Active Information Gathering")
    print(f"{Fore.BLUE}{'='*50}")
    log_output("\n# Active Information Gathering")

    if check_tool_before_scan("nmap", "Nmap TCP Scan"):
        sudo = get_sudo_prefix()
        run_command(
            f"{sudo}nmap -vv -n -sV -Pn -O -oA full_tcp -p 80,443,8080,8443 {target}", 
            "Nmap TCP Scan (requires root for -O)", 
            OUTPUT_FILE
        )
    progress_bar.update(1)

def http_methods_check(target, progress_bar):
    if yes_no("Check for allowed HTTP methods?"):
        print(f"{Fore.BLUE}\n{'='*50}")
        print(f"{Fore.BLUE}HTTP Methods Check")
        print(f"{Fore.BLUE}{'='*50}")
        log_output("\n# HTTP Methods Check")
        
        if check_tool_before_scan("nmap", "HTTP Methods Check"):
            sudo = get_sudo_prefix()
            run_command(f"{sudo}nmap --script=http-methods.nse {target}", "HTTP Methods Check", OUTPUT_FILE)
    else:
        print(f"{Fore.YELLOW}Skipping HTTP methods check.")
        log_output("HTTP methods check skipped.")
    progress_bar.update(1)

def technology_detection(target, target_type, progress_bar):
    """Technology detection using whatweb and wappalyzer"""
    print(f"{Fore.BLUE}\n{'='*50}")
    print(f"{Fore.BLUE}Technology Detection")
    print(f"{Fore.BLUE}{'='*50}")
    log_output("\n# Technology Detection")
    
    # Determine URL format
    if target_type == TargetType.DOMAIN:
        url = f"https://{target}"
    else:
        url = f"http://{target}"
    
    if check_tool_before_scan("whatweb", "WhatWeb Scan"):
        run_command(f"whatweb -v -a 3 {target}", "WhatWeb Scan", OUTPUT_FILE)
    progress_bar.update(1)
    
    if check_tool_before_scan("wappalyzer", "Wappalyzer Scan"):
        run_command(
            f"wappalyzer {url} --pretty", 
            "Wappalyzer Technology Detection", 
            OUTPUT_FILE,
            timeout=60
        )
    progress_bar.update(1)

def robots_and_sitemap(target, target_type, progress_bar):
    """Check robots.txt and sitemap.xml"""
    if target_type != TargetType.DOMAIN:
        print(f"{Fore.YELLOW}Skipping robots/sitemap check (target is IP)")
        progress_bar.update(1)
        return
    
    print(f"{Fore.BLUE}\n{'='*50}")
    print(f"{Fore.BLUE}Robots.txt and Sitemap Check")
    print(f"{Fore.BLUE}{'='*50}")
    log_output("\n# Robots.txt and Sitemap Check")
    
    if check_tool_before_scan("curl", "Robots.txt"):
        run_command(f"curl -s https://{target}/robots.txt", "Robots.txt (HTTPS)", OUTPUT_FILE)
        run_command(f"curl -s https://{target}/sitemap.xml", "Sitemap.xml (HTTPS)", OUTPUT_FILE)
    progress_bar.update(1)

def content_discovery(target, target_type, progress_bar):
    """Content discovery using ffuf"""
    if not yes_no("Perform content discovery with ffuf?"):
        print(f"{Fore.YELLOW}Skipping content discovery.")
        log_output("Content discovery skipped.")
        progress_bar.update(1)
        return
    
    print(f"{Fore.BLUE}\n{'='*50}")
    print(f"{Fore.BLUE}Content Discovery (ffuf)")
    print(f"{Fore.BLUE}{'='*50}")
    log_output("\n# Content Discovery")
    
    # Determine URL format
    if target_type == TargetType.DOMAIN:
        url = f"https://{target}/FUZZ"
    else:
        url = f"http://{target}/FUZZ"
    
    # Common wordlist locations
    wordlists = [
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
        "/opt/SecLists/Discovery/Web-Content/common.txt"
    ]
    
    # Find available wordlist
    wordlist = None
    for wl in wordlists:
        if os.path.exists(wl):
            wordlist = wl
            break
    
    if not wordlist:
        print(f"{Fore.RED}No wordlist found. Skipping content discovery.")
        log_output("Content discovery skipped - no wordlist found")
        progress_bar.update(1)
        return
    
    if check_tool_before_scan("ffuf", "Content Discovery"):
        run_command(
            f"ffuf -u {url} -w {wordlist} -mc 200,204,301,302,307,401,403 -c -t 50 -timeout 10",
            f"ffuf Content Discovery (using {os.path.basename(wordlist)})",
            OUTPUT_FILE,
            timeout=300
        )
    progress_bar.update(1)

def vulnerability_scan(target, progress_bar):
    if yes_no("Perform Vulnerability Scan with Nikto?"):
        print(f"{Fore.BLUE}\n{'='*50}")
        print(f"{Fore.BLUE}Vulnerability Scan")
        print(f"{Fore.BLUE}{'='*50}")
        log_output("\n# Vulnerability Scan")
        
        if check_tool_before_scan("nikto", "Nikto Vulnerability Scan"):
            run_command(
                f"nikto -h https://{target} -Tuning 123bde", 
                "Nikto Vulnerability Scan", 
                OUTPUT_FILE,
                timeout=600
            )
    else:
        print(f"{Fore.YELLOW}Skipping Vulnerability Scan.")
        log_output("Vulnerability scan skipped.")
    progress_bar.update(1)

def ssl_tls_scan(target, target_type, progress_bar):
    """SSL/TLS testing using testssl.sh"""
    if target_type == TargetType.IP:
        if not yes_no("Target is IP - attempt SSL/TLS scan anyway?"):
            print(f"{Fore.YELLOW}Skipping SSL/TLS scan.")
            log_output("SSL/TLS scan skipped - target is IP")
            progress_bar.update(1)
            return
    
    print(f"{Fore.BLUE}\n{'='*50}")
    print(f"{Fore.BLUE}SSL/TLS Analysis")
    print(f"{Fore.BLUE}{'='*50}")
    log_output("\n# SSL/TLS Analysis")
    
    if check_tool_before_scan("testssl", "SSL/TLS Scan"):
        # testssl.sh with reasonable options for pentesting
        run_command(
            f"testssl --color 0 -U -S -P --fast {target}",
            "testssl.sh SSL/TLS Analysis",
            OUTPUT_FILE,
            timeout=300
        )
    progress_bar.update(1)

# === Main Logic ===
def main():
    global OUTPUT_FILE
    
    parser = ArgumentParser(description="Web Reconnaissance Tool")
    parser.add_argument("--target", help="Target domain or IP address", required=False)
    parser.add_argument("--auto", help="Run without prompts", action="store_true")
    parser.add_argument("--skip-check", help="Skip tool dependency check", action="store_true")
    parser.add_argument("-o", "--output", help="Output file name", default="web_recon_output.md")
    args = parser.parse_args()

    OUTPUT_FILE = args.output

    print(f"{Fore.MAGENTA}")
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║                  Web Reconnaissance Tool                     ║")
    print("║                                                              ║")
    print("║  Tools: nmap, nikto, whatweb, wappalyzer, subfinder,        ║")
    print("║         ffuf, testssl.sh, dnsrecon, curl                    ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print(f"{Style.RESET_ALL}")

    # Check for root privileges
    if not is_root():
        print(f"{Fore.YELLOW}⚠ Not running as root. Some scans (nmap -O) will use sudo.")
        print(f"{Fore.YELLOW}  You may be prompted for your password.\n")

    # Check for required tools unless skipped
    if not args.skip_check:
        if not check_all_tools():
            print(f"{Fore.RED}Exiting due to missing tools.")
            sys.exit(1)

    # Initialize output file
    with open(OUTPUT_FILE, 'w') as f:
        f.write("# Web Reconnaissance Report\n")
        f.write("=" * 60 + "\n\n")

    if args.target:
        target_input = args.target
    else:
        target_input = prompt_user("Enter URL or IP address to be tested: ")

    target_type = validate_target(target_input)

    if not target_type:
        print(f"{Fore.RED}Invalid target. Exiting.")
        sys.exit(1)

    # Log target info
    log_output(f"**Target:** {target_input}")
    log_output(f"**Type:** {target_type.value}")
    log_output(f"**Output File:** {OUTPUT_FILE}\n")

    print(f"\n{Fore.CYAN}Target: {target_input} ({target_type.value})")
    print(f"{Fore.CYAN}Output: {OUTPUT_FILE}\n")

    progress_bar = tqdm(total=PROGRESS_STEPS, desc=f"{Fore.CYAN}Overall Progress", ncols=100)

    try:
        # Phase 1: Passive Recon
        passive_info_gathering(target_input, target_type, progress_bar)
        subdomain_enumeration(target_input, target_type, progress_bar)
        
        # Phase 2: Active Recon
        active_info_gathering(target_input, progress_bar)
        http_methods_check(target_input, progress_bar)
        
        # Phase 3: Technology Detection
        technology_detection(target_input, target_type, progress_bar)
        robots_and_sitemap(target_input, target_type, progress_bar)
        
        # Phase 4: Content Discovery
        content_discovery(target_input, target_type, progress_bar)
        
        # Phase 5: Vulnerability Scanning
        vulnerability_scan(target_input, progress_bar)
        
        # Phase 6: SSL/TLS Analysis
        ssl_tls_scan(target_input, target_type, progress_bar)
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Scan interrupted by user.")
        log_output("\n\n--- Scan interrupted by user ---")
    except Exception as e:
        print(f"{Fore.RED}Fatal error: {e}")
        log_output(f"\n\n--- Fatal error: {e} ---")
        sys.exit(1)

    log_output("\n\n" + "=" * 60)
    log_output("# Scan Complete")
    log_output("=" * 60)
    progress_bar.close()

    print(f"\n{Fore.MAGENTA}{'='*60}")
    print(f"{Fore.GREEN}All tasks completed!")
    print(f"{Fore.CYAN}Check the output file '{OUTPUT_FILE}' for full details.")
    print(f"{Fore.MAGENTA}{'='*60}\n")

if __name__ == "__main__":
    main()
