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

echo "==================================" > "$output_file"
echo "Web Recon Tool" >> "$output_file"
echo "==================================" >> "$output_file"

# Prompt user for URL
url=$(prompt_input "Enter URL to be tested: ")
echo "URL Entered: $url" >> "$output_file"

# Passive Information Gathering
echo "==================================" >> "$output_file"
echo "Performing Passive information gathering Stage" >> "$output_file"
echo "==================================" >> "$output_file"
echo "Performing DNS lookup..." >> "$output_file"
nslookup "$url" >> "$output_file"
echo "Performing DNS reconnaissance..." >> "$output_file"
dnsrecon -d "$url" >> "$output_file"

# Active Information Gathering
echo "==================================" >> "$output_file"
echo "Performing Active information gathering Stage" >> "$output_file"
echo "==================================" >> "$output_file"
echo "Performing port scanning with Nmap..." >> "$output_file"
nmap -vv -n -sV -Pn -O -oA full_tcp -p- "$url" >> "$output_file"

# HTTP Methods Check
echo "Check for allowed HTTP methods? (y/n)" >> "$output_file"
read -r input
case $input in
    [yY])
        if command_exists "nmap"; then
            echo "Nmap Scan Starting..." >> "$output_file"
            nmap --script=http-methods.nse "$url" >> "$output_file"
            echo "Nmap Scan Complete." >> "$output_file"
        else
            echo "Error: Nmap is not installed." >> "$output_file"
            exit 1
        fi
        ;;
    [nN])
        echo "HTTP methods check skipped." >> "$output_file"
        ;;
    *)
        echo "Invalid input. Please enter 'y' or 'n'." >> "$output_file"
        ;;
esac

# WhatWeb and Robots.txt Lookup
echo "Performing WhatWeb and robots.txt Lookup..." >> "$output_file"
whatweb -v -a 3 "$url" | tee what_web_output_web_Recon.txt >> "$output_file"
echo "Retrieving robots.txt file..." >> "$output_file"
curl "$url/robots.txt" | tee curl_robots_web_Recon.txt >> "$output_file"
curl "https://$url/robots.txt" | tee curl_robots_https_web_Recon.txt >> "$output_file"

# Directory Brute Force
echo "Perform Directory Brute Force? (y/n)" >> "$output_file"
read -r input
case $input in
    [yY])
        if command_exists "wfuzz"; then
            wordlist=$(prompt_input "Enter the path to custom wordlist: ")
            if [ -f "$wordlist" ]; then
                echo "Directory Brute Force Starting..." >> "$output_file"
                wfuzz -c -w "$wordlist" --hc 400,404,403 "https://$url/FUZZ" | tee wfuzz_output_web_Recon.txt >> "$output_file"
                echo "Brute Force Complete." >> "$output_file"
            else
                echo "Error: Wordlist file not found." >> "$output_file"
                exit 1
            fi
        else
            echo "Error: Wfuzz is not installed." >> "$output_file"
            exit 1
        fi
        ;;
    [nN])
        echo "Directory brute force skipped." >> "$output_file"
        ;;
    *)
        echo "Invalid input. Please enter 'y' or 'n'." >> "$output_file"
        ;;
esac

# Vulnerability Scan
echo "Perform Vulnerability Scan? (y/n)" >> "$output_file"
read -r input
case $input in
    [yY])
        if command_exists "nikto"; then
            echo "Vulnerability Scan Starting..." >> "$output_file"
            nikto -h "https://$url" | tee nikto_output.txt >> "$output_file"
            echo "Vulnerability Scan Complete." >> "$output_file"
        else
            echo "Error: Nikto is not installed." >> "$output_file"
            exit 1
        fi
        ;;
    [nN])
        echo "Vulnerability scan skipped." >> "$output_file"
        ;;
    *)
        echo "Invalid input. Please enter 'y' or 'n'." >> "$output_file"
        ;;
esac

# SSL/TLS Scan
echo "Performing SSL/TLS Scan..." >> "$output_file"
/opt/tools/testssl.sh/testssl.sh  "https://$url" | tee ssl_Scan_output.txt >> "$output_file"

echo "==================================" >> "$output_file"
echo "Script End" >> "$output_file"
echo "==================================" >> "$output_file"
