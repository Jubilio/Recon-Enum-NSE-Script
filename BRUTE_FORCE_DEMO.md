# Brute Force Attack Demonstrations

**Author: Jubilio Mausse**

## Overview

This document demonstrates the brute force attack capabilities integrated into the recon-enum.nse script. The script now includes sophisticated brute force modules for various services.

## Implemented Brute Force Modules

### 1. HTTP Directory Bruteforcing

**Target Services**: HTTP/HTTPS (ports 80, 443)

**Attack Method**: Directory and file enumeration using common paths

**Wordlist Includes**:
```
admin, administrator, login, wp-admin, dashboard, panel
backup, backups, old, tmp, temp, test, dev, config
includes, uploads, images, css, js, api, v1, v2
phpmyadmin, mysql, database, db, sql, ftp, ssh
git, .git, .svn, .hg, robots.txt, sitemap.xml
```

**Usage Example**:
```bash
# Enable directory bruteforcing
nmap -p 80,443 --script recon-enum --script-args recon-enum.bruteforce=true target.com

# Aggressive mode with directory bruteforcing
nmap -p 80,443 --script recon-enum --script-args recon-enum.aggressive=true,recon-enum.bruteforce=true target.com
```

**Sample Output**:
```
| bruteforce_results:
|   directory_bruteforce:
|     scan_type: Directory Bruteforce
|     discovered_paths:
|       - path: /admin, status: 200, size: 1024
|       - path: /login, status: 403, note: Protected/Forbidden - Potential target
|       - path: /backup, status: 401, note: Protected/Forbidden - Potential target
```

### 2. SSH Credential Bruteforcing

**Target Services**: SSH (port 22)

**Attack Method**: Common username/password combinations

**Credential List**:
```
root:root, root:toor, root:admin
admin:admin, admin:password, admin:123456
user:user, test:test, guest:guest
pi:raspberry
```

**Usage Example**:
```bash
# SSH brute force attack
nmap -p 22 --script recon-enum --script-args recon-enum.bruteforce=true target.com
```

**Sample Output**:
```
| bruteforce_results:
|   ssh_bruteforce:
|     scan_type: SSH Credential Bruteforce
|     attempted_credentials:
|       - root:root
|       - root:toor
|       - admin:admin
|     total_attempts: 10
|     successful_logins: []
```

### 3. FTP Credential Bruteforcing

**Target Services**: FTP (port 21)

**Attack Method**: Anonymous and common credential testing

**Credential List**:
```
anonymous:
anonymous:anonymous
ftp:ftp
admin:admin
root:root
user:user
```

**Usage Example**:
```bash
# FTP brute force attack
nmap -p 21 --script recon-enum --script-args recon-enum.bruteforce=true target.com
```

**Sample Output**:
```
| bruteforce_results:
|   ftp_bruteforce:
|     scan_type: FTP Credential Bruteforce
|     attempted_credentials:
|       - anonymous:
|       - ftp:ftp
|       - admin:admin
|     ftp_banner: 220 Welcome to FTP Server
```

### 4. Database Credential Bruteforcing

**Target Services**: MySQL (3306), PostgreSQL (5432), SQL Server (1433)

**Attack Method**: Default and common database credentials

**Credential List**:
```
root:, root:root
admin:admin
sa:, sa:sa
postgres:postgres
mysql:mysql
```

**Usage Example**:
```bash
# Database brute force attack
nmap -p 3306,5432,1433 --script recon-enum --script-args recon-enum.bruteforce=true target.com
```

**Sample Output**:
```
| bruteforce_results:
|   database_bruteforce:
|     scan_type: MYSQL Database Bruteforce
|     service_type: mysql
|     attempted_credentials:
|       - root:
|       - root:root
|       - admin:admin
```

## Advanced Features

### Combined Attack Modes

**Aggressive + Brute Force**:
```bash
nmap --script recon-enum --script-args recon-enum.aggressive=true,recon-enum.bruteforce=true target.com
```

This enables:
- Directory bruteforcing
- Credential testing
- Advanced SSL/TLS analysis
- Network timing analysis

### Protocol-Specific Attacks

**Web Application Focus**:
```bash
nmap -p 80,443 --script recon-enum --script-args recon-enum.protocols=http,recon-enum.bruteforce=true target.com
```

**Infrastructure Focus**:
```bash
nmap --script recon-enum --script-args recon-enum.protocols=ssh,ftp,recon-enum.bruteforce=true target.com
```

**Database Focus**:
```bash
nmap --script recon-enum --script-args recon-enum.protocols=mysql,postgresql,recon-enum.bruteforce=true target.com
```

## Security Considerations

### Ethical Use Guidelines

1. **Authorization Required**: Only use on systems you own or have explicit permission to test
2. **Rate Limiting**: Script includes timeouts to prevent DoS
3. **Legal Compliance**: Ensure compliance with local laws and regulations
4. **Responsible Disclosure**: Report vulnerabilities responsibly

### Detection Avoidance

1. **Timing Controls**: Use custom timeouts to avoid detection
   ```bash
   --script-args recon-enum.timeout=10
   ```

2. **Stealth Scanning**: Combine with nmap timing options
   ```bash
   nmap -T1 --script recon-enum --script-args recon-enum.bruteforce=true target.com
   ```

3. **Decoy Scanning**: Use multiple source IPs
   ```bash
   sudo nmap -D 192.168.1.100,192.168.1.101 --script recon-enum target.com
   ```

## Performance Optimization

### Timeout Configuration
```bash
# Fast scanning (2 second timeout)
--script-args recon-enum.timeout=2

# Standard scanning (5 second timeout - default)
--script-args recon-enum.timeout=5

# Slow/careful scanning (15 second timeout)
--script-args recon-enum.timeout=15
```

### Service Targeting
```bash
# Target only web services
--script-args recon-enum.protocols=http

# Target only SSH services
--script-args recon-enum.protocols=ssh

# Target multiple specific services
--script-args recon-enum.protocols=http,ssh,ftp
```

## Real-World Use Cases

### 1. Web Application Penetration Testing
```bash
# Comprehensive web app assessment
nmap -sV -p 80,443,8080,8443 --script recon-enum \
--script-args recon-enum.aggressive=true,recon-enum.bruteforce=true \
target-webapp.com
```

### 2. Infrastructure Security Audit
```bash
# Network infrastructure assessment
nmap -sS --script recon-enum \
--script-args recon-enum.bruteforce=true,recon-enum.protocols=ssh,ftp,telnet \
192.168.1.0/24
```

### 3. Database Security Testing
```bash
# Database server assessment
nmap -p 1433,3306,5432 --script recon-enum \
--script-args recon-enum.bruteforce=true,recon-enum.protocols=mysql,postgresql,ms-sql-s \
db-server.company.com
```

### 4. Red Team Exercise
```bash
# Comprehensive red team assessment
nmap -sS -sV -O --script recon-enum \
--script-args recon-enum.aggressive=true,recon-enum.bruteforce=true \
-T3 target-network.com
```

## Integration with Other Tools

### Export Results for Further Analysis
```bash
# XML output for parsing
nmap --script recon-enum -oX results.xml target.com

# Grep-able output
nmap --script recon-enum -oG results.gnmap target.com

# All formats
nmap --script recon-enum -oA comprehensive-scan target.com
```

### Combine with Other NSE Scripts
```bash
# With vulnerability scripts
nmap --script "recon-enum,vuln" target.com

# With HTTP enumeration
nmap --script "recon-enum,http-*" -p 80,443 target.com

# With SMB scripts
nmap --script "recon-enum,smb-*" -p 139,445 target.com
```

## Troubleshooting

### Common Issues and Solutions

1. **Timeouts**: Increase timeout value
2. **False Positives**: Review discovered paths manually
3. **Rate Limiting**: Reduce scan speed with -T options
4. **Permissions**: Use sudo for certain scan types

### Debug Mode
```bash
# Enable debug output
nmap -d --script recon-enum target.com

# Verbose output
nmap -v --script recon-enum target.com
```