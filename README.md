# Recon-Enum NSE Script

## 👨‍💻 Autor
**Author: Jubilio Mausse**

LinkedIn: [https://github.com/Jubilio/]  
GitHub: [www.linkedin.com/in/jubilio-mausse]

## Overview

The `recon-enum.nse` script is a comprehensive Nmap Scripting Engine (NSE) script designed for network reconnaissance and security testing. This script combines multiple reconnaissance techniques to provide detailed information about target hosts and services.

## Features

### Core Reconnaissance
- **Service Banner Grabbing**: Captures service banners for identification
- **HTTP Header Analysis**: Analyzes web server headers and configurations
- **SSL/TLS Information**: Gathers SSL certificate and encryption details
- **SMB Enumeration**: Basic SMB service detection and analysis
- **Service-Specific Checks**: Tailored reconnaissance for common services
- **Security Recommendations**: Provides security improvement suggestions
- **Comprehensive Output**: Structured and detailed reconnaissance results

### Advanced Intelligence Gathering
- **Open Port Scanner**: Automated discovery of open ports on target systems
- **Target Intelligence**: Comprehensive information extraction including OS, network, and service details
- **Web Intelligence**: Technology detection, security headers analysis, and cookie examination
- **Database Intelligence**: Specialized enumeration for MySQL, PostgreSQL, and SQL Server
- **SSH Intelligence**: Version detection and algorithm analysis

### Security Testing Features
- **Brute Force Attacks**: Credential testing for SSH, FTP, HTTP, and database services
- **Directory Bruteforcing**: Automated discovery of hidden web directories and files
- **Advanced SSL/TLS Analysis**: Cipher suite analysis and vulnerability checking
- **Network Timing Analysis**: Response time measurement and network fingerprinting
- **Vulnerability Assessments**: Common security weakness identification

## Installation

1. Copy the `recon-enum.nse` script to your Nmap scripts directory:
   ```bash
   sudo cp recon-enum.nse /usr/share/nmap/scripts/

2. Update the script database:
   ```bash
   sudo nmap --script-updatedb

3. Verify installation:
   ```bash
   nmap --script-help recon-enum

## Usage Examples

### Basic Scanning
```bash
# Basic reconnaissance scan
nmap --script recon-enum target.com

# Scan with OS detection
nmap -O --script recon-enum target.com

# Aggressive scan with service detection
nmap -sV -O --script recon-enum target.com
```

### Advanced Options
```bash
# Custom timeout for slow networks
nmap --script recon-enum --script-args recon-enum.timeout=10 target.com

# Aggressive mode (includes advanced analysis)
nmap --script recon-enum --script-args recon-enum.aggressive=true target.com

# Enable brute force attacks
nmap --script recon-enum --script-args recon-enum.bruteforce=true target.com

# Combined aggressive and brute force mode
nmap --script recon-enum --script-args recon-enum.aggressive=true,recon-enum.bruteforce=true target.com

# Target specific protocols only
nmap --script recon-enum --script-args recon-enum.protocols=http,ssh target.com
```

### Professional Use Cases
```bash
# Web application security assessment
nmap -p 80,443 --script recon-enum --script-args recon-enum.aggressive=true,recon-enum.bruteforce=true target.com

# Network infrastructure audit
nmap --script recon-enum --script-args recon-enum.protocols=ssh,ftp,telnet 192.168.1.0/24

# Database security testing
nmap --script recon-enum --script-args recon-enum.bruteforce=true,recon-enum.protocols=mysql,postgresql target.com
   
