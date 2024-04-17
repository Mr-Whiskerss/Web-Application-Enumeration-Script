# Web App enumeration script. This is version 0.6 of the script. It is still in devlopment stage more tools to be added soon!
# Please contact me over on github or twitter if you have any feedback! https://twitter.com/SecMrwhiskers

#!/bin/bash

# Ensure script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

# Function to display a message and wait for user input
prompt_input() {
    local message=$1
    local response
    read -p "$message" response
    echo "$response"
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Output file
output_file="web_recon_output.md"

echo "==================================" > 
echo "Web Recon Tool" >> 
echo "==================================" >> 

# Prompt user for URL
url=$(prompt_input "Enter URL to be tested: ")
echo "URL Entered: $url" >> "$output_file"

# Passive Information Gathering
echo "==================================" >> "
echo "Performing Passive information gathering Stage" >> "
echo "==================================" >> "
echo "Performing DNS lookup..." >> "
nslookup "$url" >> "$output_file"
echo "Performing DNS reconnaissance..." >> "
dnsrecon -d "$url" >> "$output_file"

# Active Information Gathering
echo "==================================" >> "
echo "Performing Active information gathering Stage" >> "
echo "==================================" >> 
echo "Performing port scanning with Nmap..." >> "
nmap -vv -n -sV -Pn -O -oA full_tcp -p- "$url" >> "$output_file"

# HTTP Methods Check
echo "Check for allowed HTTP methods? (y/n)" >> "$output_file"
read -r input
case $input in
    [yY])
        if command_exists "nmap"; then
            echo "Nmap Scan Starting..." >> 
            nmap --script=http-methods.nse "$url" >> "$output_file"
            echo "Nmap Scan Complete." >> 
        else
            echo "Error: Nmap is not installed." >> 
            exit 1
        fi
        ;;
    [nN])
        echo "HTTP methods check skipped." >> 
        ;;
    *)
        echo "Invalid input. Please enter 'y' or 'n'." >> 
        ;;
esac

# WhatWeb and Robots.txt Lookup
echo "Performing WhatWeb and robots.txt Lookup..." >> 
whatweb -v -a 3 "$url" | tee what_web_output_web_Recon.txt >> "$output_file"
echo "Retrieving robots.txt file..." >> 
curl "$url/robots.txt" | tee curl_robots_web_Recon.txt >> "$output_file"
curl "https://$url/robots.txt" | tee curl_robots_https_web_Recon.txt >> "$output_file"

# Directory Brute Force
echo "Perform Directory Brute Force? (y/n)" >> 
read -r input
case $input in
    [yY])
        if command_exists "wfuzz"; then
            wordlist=$(prompt_input "Enter the path to custom wordlist: ")
            if [ -f "$wordlist" ]; then
                echo "Directory Brute Force Starting..." >> 
                wfuzz -c -w "$wordlist" --hc 400,404,403 "https://$url/FUZZ" | tee wfuzz_output_web_Recon.txt >> "$output_file"
                echo "Brute Force Complete." >> 
            else
                echo "Error: Wordlist file not found." >> 
                exit 1
            fi
        else
            echo "Error: Wfuzz is not installed." >> 
            exit 1
        fi
        ;;
    [nN])
        echo "Directory brute force skipped." >> 
        ;;
    *)
        echo "Invalid input. Please enter 'y' or 'n'." >> 
        ;;
esac

# Vulnerability Scan
echo "Perform Vulnerability Scan? (y/n)" >> 
read -r input
case $input in
    [yY])
        if command_exists "nikto"; then
            echo "Vulnerability Scan Starting..." >> 
            nikto -h "https://$url" | tee nikto_output.txt >> "$output_file"
            echo "Vulnerability Scan Complete." >> 
        else
            echo "Error: Nikto is not installed." >> 
            exit 1
        fi
        ;;
    [nN])
        echo "Vulnerability scan skipped." >> 
        ;;
    *)
        echo "Invalid input. Please enter 'y' or 'n'." >> 
        ;;
esac

# SSL/TLS Scan
echo "Performing SSL/TLS Scan..." >> 
/opt/tools/testssl.sh/testssl.sh  "https://$url" | tee ssl_Scan_output.txt >> "$output_file"

echo "==================================" >> "
echo "Script End" >> 
echo "==================================" >> 
