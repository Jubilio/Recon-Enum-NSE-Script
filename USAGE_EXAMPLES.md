# Recon-Enum NSE Script Usage Examples

## Basic Usage Examples

### 1. Simple Target Scan
```bash
# Basic reconnaissance scan
nmap --script recon-enum target.com

# Scan specific ports
nmap -p 80,443,22 --script recon-enum target.com
```

### 2. Using Script Arguments
```bash
# Extended timeout for slow networks
nmap --script recon-enum --script-args recon-enum.timeout=10 target.com

# Aggressive mode with directory bruteforcing
nmap --script recon-enum --script-args recon-enum.aggressive=true target.com

# Target specific protocols only
nmap --script recon-enum --script-args recon-enum.protocols=http,ssh target.com
```

### 3. Combined with Nmap Features
```bash
# With OS detection
nmap -O --script recon-enum target.com

# With service version detection
nmap -sV --script recon-enum target.com

# Full comprehensive scan
nmap -sS -sV -O --script recon-enum target.com
```

## Advanced Usage Scenarios

### 4. Network Range Scanning
```bash
# Scan entire subnet
nmap --script recon-enum 192.168.1.0/24

# Multiple targets
nmap --script recon-enum target1.com target2.com target3.com
```

### 5. Stealth Scanning
```bash
# Slow stealth scan
nmap -sS -T1 --script recon-enum target.com

# Decoy scanning (requires root)
sudo nmap -sS -D 192.168.1.100,192.168.1.101 --script recon-enum target.com
```

### 6. Web Application Focus
```bash
# Focus on web services only
nmap -p 80,443,8080,8443 --script recon-enum --script-args recon-enum.protocols=http target.com

# Aggressive web enumeration
nmap -p 80,443 --script recon-enum --script-args recon-enum.aggressive=true,recon-enum.timeout=15 target.com
```

## Sample Output Interpretation

### Target Intelligence Output
```
| recon-enum:
|   target_intelligence:
|     target_info:
|       ip_address: 192.168.1.100
|       hostname: webserver.local
|       port: 80
|       service: http
|       protocol: tcp
|     web_intelligence:
|       server_software: Apache/2.4.41
|       technologies: 
|         - PHP/7.4.3
|       security_headers:
|         x-frame-options: SAMEORIGIN
|       cookies: PHPSESSID=abc123; path=/
|     collection_timestamp: 2025-07-18 10:30:00 UTC
```

### Port Scan Results
```
|   port_scan:
|     scan_method: TCP Connect Scan
|     total_open: 4
|     open_ports:
|       - port: 22, state: open, service: ssh
|       - port: 80, state: open, service: http
|       - port: 443, state: open, service: https
|       - port: 3306, state: open, service: mysql
```

## Integration with Other Tools

### 7. Export Results for Analysis
```bash
# XML output for further processing
nmap --script recon-enum -oX scan_results.xml target.com

# Grep-able output
nmap --script recon-enum -oG scan_results.gnmap target.com

# All formats
nmap --script recon-enum -oA scan_results target.com
```

### 8. Combine with Other NSE Scripts
```bash
# With vulnerability scanning
nmap --script "recon-enum,vuln" target.com

# With HTTP enumeration scripts
nmap --script "recon-enum,http-*" -p 80,443 target.com

# With database scripts
nmap --script "recon-enum,mysql-*,ms-sql-*" target.com
```

## Security Testing Workflows

### 9. External Network Assessment
```bash
# Step 1: Discovery
nmap -sn 192.168.1.0/24

# Step 2: Port scanning
nmap -sS --top-ports 1000 192.168.1.0/24

# Step 3: Service enumeration
nmap --script recon-enum -sV 192.168.1.0/24
```

### 10. Web Application Testing
```bash
# Step 1: Identify web services
nmap -p 80,443,8080,8443 --script recon-enum target.com

# Step 2: Deep web enumeration  
nmap -p 80,443 --script "recon-enum,http-*" --script-args recon-enum.aggressive=true target.com

# Step 3: SSL/TLS analysis
nmap -p 443 --script "recon-enum,ssl-*" target.com
```

## Troubleshooting Common Issues

### Script Not Found
```bash
# Update script database
sudo nmap --script-updatedb

# Check script location
find /usr -name "recon-enum.nse" 2>/dev/null
```

### Permission Issues
```bash
# Some scans require root privileges
sudo nmap --script recon-enum target.com

# Check current permissions
whoami
id
```

### Network Connectivity
```bash
# Test basic connectivity
ping target.com

# Check specific port
telnet target.com 80
nc -zv target.com 80
```

## Best Practices

1. **Always get authorization** before scanning external targets
2. **Start with basic scans** before using aggressive modes
3. **Use appropriate timing** (-T0 to -T5) based on network conditions
4. **Combine with OS detection** (-O) for better intelligence
5. **Save results** in multiple formats for analysis
6. **Review logs** for any errors or timeouts
7. **Respect rate limits** to avoid being blocked
8. **Use decoys** for stealth when necessary
9. **Document findings** for reporting and remediation
10. **Follow responsible disclosure** for any vulnerabilities found