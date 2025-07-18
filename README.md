# Recon-Enum NSE Script

## Overview

The `recon-enum.nse` script is a comprehensive Nmap Scripting Engine (NSE) script designed for network reconnaissance and security testing. This script combines multiple reconnaissance techniques to provide detailed information about target hosts and services.

## Features

- **Service Banner Grabbing**: Captures service banners for identification
- **HTTP Header Analysis**: Analyzes web server headers and configurations
- **SSL/TLS Information**: Gathers SSL certificate and encryption details
- **SMB Enumeration**: Basic SMB service detection and analysis
- **Service-Specific Checks**: Tailored reconnaissance for common services
- **Security Recommendations**: Provides security improvement suggestions
- **Comprehensive Output**: Structured and detailed reconnaissance results

## Installation

1. Copy the `recon-enum.nse` script to your Nmap scripts directory:
   ```bash
   sudo cp recon-enum.nse /usr/share/nmap/scripts/
   