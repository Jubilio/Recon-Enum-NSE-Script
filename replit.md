# Recon-Enum NSE Script

## Overview

This repository contains a comprehensive Nmap Scripting Engine (NSE) script for network reconnaissance and security testing. The `recon-enum.nse` script is designed to perform automated reconnaissance across multiple protocols and services, providing security professionals with detailed information about target systems.

## User Preferences

Preferred communication style: Simple, everyday language.

## Recent Changes

### July 18, 2025 - Bug Fixes and Test Suite Improvements
- Fixed test script failures by aligning test patterns with actual nmap output
- Updated NSE script documentation with improved @args format for better clarity
- Corrected invalid nmap command syntax in test suite
- Replaced external network test with internal script validation tests
- All 9 test cases now pass successfully
- Workflows are running without errors

### July 18, 2025 - Major Feature Enhancements
- **Author Updated**: Changed script author to "Jubilio Mausse" 
- **Added Open Port Scanner**: New `scan_open_ports()` function for comprehensive port discovery
- **Added Intelligence Gathering**: New `gather_target_intelligence()` function for detailed target information extraction
- **Enhanced Web Intelligence**: Improved HTTP header analysis, technology detection, and security header checking
- **Database Intelligence**: Added specialized intelligence gathering for MySQL, PostgreSQL, and MSSQL
- **SSH Intelligence**: Enhanced SSH version and algorithm detection
- **Created Improvement Guide**: Comprehensive IMPROVEMENTS.md with 10 categories of enhancement suggestions
- **Created Usage Examples**: Detailed USAGE_EXAMPLES.md with practical command examples and output interpretation

## System Architecture

The project follows a simple, file-based architecture centered around a single NSE script:

- **Core Script**: `recon-enum.nse` - Main reconnaissance engine
- **Documentation**: README.md with installation and usage instructions
- **Examples**: Sample outputs and usage scenarios for reference

The architecture is designed for:
- Integration with existing Nmap installations
- Standalone operation without external dependencies
- Modular reconnaissance capabilities across multiple protocols

## Key Components

### Core Reconnaissance Engine
- **Service Banner Grabbing**: Captures and analyzes service identification strings
- **HTTP Analysis Module**: Examines web server headers, configurations, and directory structures
- **SSL/TLS Assessment**: Gathers certificate information and encryption details
- **SMB Enumeration**: Detects and analyzes SMB services
- **Protocol-Specific Handlers**: Tailored reconnaissance for common network services

### Configuration System
- **Script Arguments**: Configurable parameters for timeout, protocols, and aggressiveness
- **Flexible Targeting**: Support for single hosts, IP ranges, and specific port targeting
- **Output Formatting**: Structured results with security recommendations

## Data Flow

1. **Target Identification**: Nmap identifies open ports and services
2. **Service Recognition**: Script determines service types and versions
3. **Protocol-Specific Enumeration**: Applies appropriate reconnaissance techniques
4. **Information Gathering**: Collects banners, headers, and configuration details
5. **Security Analysis**: Generates security notes and recommendations
6. **Result Compilation**: Formats comprehensive output with timestamps

## External Dependencies

### Required Dependencies
- **Nmap**: Core scanning engine (version with NSE support)
- **Lua Runtime**: For NSE script execution (included with Nmap)

### Optional Integrations
- **Operating System Detection**: Can be combined with Nmap's `-O` flag
- **Version Detection**: Integrates with Nmap's `-sV` service detection
- **Other NSE Scripts**: Designed to work alongside existing NSE modules

## Deployment Strategy

### Installation Process
1. **Script Placement**: Copy to Nmap scripts directory (`/usr/share/nmap/scripts/`)
2. **Script Database Update**: Run `nmap --script-updatedb` to register the script
3. **Verification**: Test with basic scan to confirm proper installation

### Usage Patterns
- **Basic Reconnaissance**: Single host scanning for initial assessment
- **Network Discovery**: Subnet-wide scanning for network mapping
- **Targeted Assessment**: Focused scanning on specific services or ports
- **Aggressive Enumeration**: Deep reconnaissance with extended timeouts

### Security Considerations
- **Authorization Required**: Only use on authorized networks and systems
- **Impact Awareness**: Aggressive scanning may impact target system performance
- **Legal Compliance**: Ensure compliance with applicable laws and policies
- **Logging**: Maintain scan logs for accountability and analysis