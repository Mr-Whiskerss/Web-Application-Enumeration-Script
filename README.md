![image](https://github.com/user-attachments/assets/72200de9-91c6-43b5-8a15-266951917b4b)


🕸️ Web Application Enumeration Script
A lightweight Python-based script that automates the initial stages of web application enumeration, helping pentesters save time during engagements.

📖 Overview
Originally developed as a basic Bash script, this project has evolved into a more powerful and flexible Python tool.
It automates many essential tasks for quickly assessing web infrastructure security — especially during manual pentesting.
Note: This tool generates considerable traffic and is not recommended for stealthy Red Team operations.

🛠️ Features
Enumerate single IP addresses or domain names

Automate basic recon and vulnerability detection

Integrate commonly used tools into one workflow

Provide evidence quickly for web security assessments

📦 Required Tools
Make sure the following are installed system-wide:

```
nslookup
dnsrecon
nmap
whatweb
curl
nikto
tlsscan
```

🚀 Getting Started
Clone or download the repository.

Make the script executable:
```
chmod +x Web-Application-Enumeration.V1.0.py
```
Run the script:
```
python3 ./Web-Application-Enumeration.V1.0.py
```
Enter the target IP address or URL when prompted.

🧪 Development Version
A new dev version (Web-Application-Enumeration.V1.1-dev_Miguel.py) is under active improvement.

You can test it, but for stability, use V1.0.

🔥 Upcoming Features
Directory brute-forcing (dirb integration)

JavaScript library enumeration

Virtual hosting discovery

Multi-host scanning support

📜 License
This project is licensed under the GNU GPL-3.0 License.
