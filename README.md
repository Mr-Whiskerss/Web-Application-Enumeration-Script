# Web-Application-Enumeration-Script
This started off as a basic bash script to run some basic web application enumeration. 
I have evolved this into a python script. The goal of the script remains the same. The old bash scripts up to version 0.6 can be found in the folder within this repo.


### Descrpiton 
This is just a basic python script that can be run agaianst a single IP address running a web server or a URL. I have included some examples below on how to run it. Please ensure the tools list below are installed system wide otherwise you will get some errors. I have tried to include error handling were possible. However this is still in dev stages. 

The goal of this script is to remove some of the manual work when testing web infrastructre and providing evdience. This script is only designed to be run in a normal pentest not suitable for redteaming due to the volume of traffic thrown at the host.


### Tools that need to be installed for this script to work.
* nslookup
* DNSrecon
* Nmap
* WhatWeb
* Curl
* Nikto
* TLS Scan

### Running the tool

Download the Web-Application-Enumeration.V1.0.py file to your local machine
chmod +x the file
run - python3 ./Web-Application-Enumeration.V1.0.py
enter URL or IP address you want to enumerate. 

#### Up coming changes I wish to make

* Add more tools to find more issues such as dirb for directory brute forcing
* Add a feature to grab java script libaries from web application for further investigation.
* Add virtual hosting enumeration options.
* Add multiple hosts to scan.








