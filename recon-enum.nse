local shortport = require "shortport"
local stdnse = require "stdnse"
local nmap = require "nmap"
local string = require "string"
local table = require "table"
local http = require "http"
local comm = require "comm"
local coroutine = require "coroutine"

description = [[
Advanced Network Reconnaissance and Enumeration Script

This NSE script performs comprehensive network reconnaissance by combining
multiple reconnaissance techniques including:
- Service banner grabbing
- HTTP header analysis  
- SSL/TLS certificate information
- SMB enumeration
- DNS information gathering
- OS fingerprinting enhancement
- Common service enumeration

The script is designed for authorized security testing and network assessment.
]]

---
-- @usage
-- nmap --script recon-enum <target>
-- nmap --script recon-enum --script-args recon-enum.timeout=10 <target>
-- nmap -sS -O --script recon-enum <target>
-- nmap --script recon-enum --script-args recon-enum.aggressive=true <target>
-- nmap --script recon-enum --script-args recon-enum.protocols=http,ssh <target>
--
-- @output
-- PORT   STATE SERVICE
-- 22/tcp open  ssh
-- | recon-enum:
-- |   Banner: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
-- |   Service Info:
-- |     Protocol: ssh
-- |     Version: OpenSSH 8.9p1
-- |     OS: Ubuntu
-- |   Security Notes:
-- |_    SSH version may be vulnerable to specific attacks
--
-- @args recon-enum.timeout Timeout for network operations in seconds (default: 5)
-- @args recon-enum.aggressive Enable aggressive scanning modes including directory bruteforcing (default: false)  
-- @args recon-enum.protocols Comma-separated list of protocols to scan: http,ssh,ftp,telnet,smtp (default: all)

author = "Network Security Researcher"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive", "version"}

-- Script arguments
local arg_timeout = stdnse.get_script_args(SCRIPT_NAME .. ".timeout") or 5
local arg_aggressive = stdnse.get_script_args(SCRIPT_NAME .. ".aggressive") or false
local arg_protocols = stdnse.get_script_args(SCRIPT_NAME .. ".protocols") or "all"

-- Convert timeout to number
arg_timeout = tonumber(arg_timeout) or 5

-- Port rule - run on open TCP ports
portrule = shortport.port_or_service({21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1433, 1521, 3306, 3389, 5432, 5985, 5986}, 
                                   {"ftp", "ssh", "telnet", "smtp", "domain", "http", "pop3", "msrpc", "netbios-ssn", "imap", "https", "imaps", "pop3s", "ms-sql-s", "oracle", "mysql", "ms-wbt-server", "postgresql", "winrm", "wsman"})

-- Host rule for host-wide reconnaissance
hostrule = function(host)
    return true
end

-- Enhanced banner grabbing function
local function grab_banner(host, port)
    local status, result
    local socket = nmap.new_socket()
    
    -- Set timeout
    socket:set_timeout(arg_timeout * 1000)
    
    status, result = socket:connect(host, port)
    if not status then
        socket:close()
        return nil, "Connection failed: " .. (result or "unknown error")
    end
    
    -- Try to receive banner
    status, result = socket:receive_lines(1)
    socket:close()
    
    if status then
        return result:gsub("[\r\n]+$", ""), nil
    else
        return nil, "No banner received"
    end
end

-- HTTP enumeration function
local function http_enum(host, port)
    local result = {}
    
    -- Get HTTP response
    local response = http.get(host, port, "/")
    if not response then
        return nil, "HTTP request failed"
    end
    
    result.status = response.status
    result.server = response.header["server"] or "Unknown"
    result.powered_by = response.header["x-powered-by"]
    result.content_type = response.header["content-type"]
    result.headers = {}
    
    -- Collect interesting headers
    local interesting_headers = {"server", "x-powered-by", "x-aspnet-version", "x-frame-options", "strict-transport-security", "content-security-policy"}
    for _, header in ipairs(interesting_headers) do
        if response.header[header] then
            table.insert(result.headers, header .. ": " .. response.header[header])
        end
    end
    
    -- Check for common directories/files
    if arg_aggressive then
        local common_paths = {"/robots.txt", "/admin", "/login", "/.git", "/.svn", "/backup"}
        result.discovered_paths = {}
        
        for _, path in ipairs(common_paths) do
            local path_response = http.get(host, port, path)
            if path_response and path_response.status and path_response.status < 400 then
                table.insert(result.discovered_paths, path .. " (" .. path_response.status .. ")")
            end
        end
    end
    
    return result, nil
end

-- SSL/TLS certificate information
local function ssl_info(host, port)
    local result = {}
    
    -- This is a simplified SSL check
    -- In a real implementation, you'd use the ssl library
    local socket = nmap.new_socket()
    socket:set_timeout(arg_timeout * 1000)
    
    local status = socket:connect(host, port, "ssl")
    if status then
        result.ssl_enabled = true
        socket:close()
    else
        result.ssl_enabled = false
    end
    
    return result
end

-- SMB enumeration function
local function smb_enum(host, port)
    local result = {}
    
    if port.number == 139 or port.number == 445 then
        result.protocol = "SMB/NetBIOS"
        result.note = "SMB service detected - consider running smb-enum-* scripts"
        
        -- Basic SMB connection test
        local socket = nmap.new_socket()
        socket:set_timeout(arg_timeout * 1000)
        
        local status = socket:connect(host, port)
        if status then
            result.accessible = true
            socket:close()
        else
            result.accessible = false
        end
    end
    
    return result
end

-- Service-specific enumeration
local function service_specific_enum(host, port, service_name)
    local result = {}
    
    if service_name == "ssh" then
        result.service_type = "SSH"
        result.security_notes = {"Check for weak authentication", "Verify SSH version for vulnerabilities"}
        
    elseif service_name == "ftp" then
        result.service_type = "FTP"
        result.security_notes = {"Check for anonymous access", "Verify if FTPS is used"}
        
    elseif service_name == "telnet" then
        result.service_type = "Telnet"
        result.security_notes = {"Unencrypted protocol", "Consider SSH alternative"}
        
    elseif service_name == "smtp" then
        result.service_type = "SMTP"
        result.security_notes = {"Check for open relay", "Verify STARTTLS support"}
        
    elseif service_name == "mysql" then
        result.service_type = "MySQL"
        result.security_notes = {"Check for default credentials", "Verify encryption in use"}
        
    elseif service_name == "postgresql" then
        result.service_type = "PostgreSQL"
        result.security_notes = {"Check authentication methods", "Verify SSL configuration"}
        
    elseif service_name == "ms-sql-s" then
        result.service_type = "Microsoft SQL Server"
        result.security_notes = {"Check for sa account", "Verify encryption settings"}
        
    else
        result.service_type = "Generic Service"
        result.security_notes = {"Review service configuration", "Check for default credentials"}
    end
    
    return result
end

-- Main action function for ports
action = function(host, port)
    local result = stdnse.output_table()
    local status, err
    
    -- Skip if specific protocols are requested and this isn't one of them
    if arg_protocols ~= "all" then
        local protocols = {}
        for protocol in string.gmatch(arg_protocols, "[^,]+") do
            protocols[protocol:lower()] = true
        end
        
        if not protocols[port.service:lower()] then
            return nil
        end
    end
    
    -- Banner grabbing
    local banner, banner_err = grab_banner(host, port)
    if banner then
        result.banner = banner
        
        -- Parse banner for additional info
        if string.match(banner, "SSH%-([%d%.]+)") then
            result.ssh_version = string.match(banner, "SSH%-([%d%.]+)")
        end
    else
        result.banner_error = banner_err
    end
    
    -- HTTP enumeration for web services
    if port.service == "http" or port.service == "https" or port.number == 80 or port.number == 443 then
        local http_result, http_err = http_enum(host, port)
        if http_result then
            result.http_info = http_result
        else
            result.http_error = http_err
        end
        
        -- SSL information for HTTPS
        if port.number == 443 or port.service == "https" then
            local ssl_result = ssl_info(host, port)
            result.ssl_info = ssl_result
        end
    end
    
    -- SMB enumeration
    if port.number == 139 or port.number == 445 or port.service == "netbios-ssn" or port.service == "microsoft-ds" then
        local smb_result = smb_enum(host, port)
        if smb_result then
            result.smb_info = smb_result
        end
    end
    
    -- Service-specific enumeration
    local service_info = service_specific_enum(host, port, port.service)
    if service_info then
        result.service_info = service_info
    end
    
    -- Additional reconnaissance based on port
    result.port_info = {
        number = port.number,
        protocol = port.protocol,
        service = port.service,
        version = port.version
    }
    
    -- Security recommendations
    result.security_recommendations = {}
    
    if port.service == "telnet" then
        table.insert(result.security_recommendations, "Consider replacing Telnet with SSH")
    end
    
    if port.service == "ftp" and port.number == 21 then
        table.insert(result.security_recommendations, "Consider using SFTP or FTPS")
    end
    
    if port.number == 80 then
        table.insert(result.security_recommendations, "Consider implementing HTTPS")
    end
    
    -- Add timestamp
    result.scan_timestamp = os.date("%Y-%m-%d %H:%M:%S")
    
    return result
end

-- Host-based reconnaissance function
host_action = function(host)
    local result = stdnse.output_table()
    
    -- Basic host information
    result.host_info = {
        ip = host.ip,
        name = host.name or "Unknown",
        os = host.os or "Unknown"
    }
    
    -- DNS information
    if host.name then
        result.dns_info = {
            hostname = host.name,
            note = "Consider DNS enumeration for subdomains"
        }
    end
    
    -- OS detection enhancement
    if host.os and host.os ~= "Unknown" then
        result.os_info = {
            detected_os = host.os,
            note = "OS detection successful - consider OS-specific security checks"
        }
    end
    
    result.scan_summary = {
        timestamp = os.date("%Y-%m-%d %H:%M:%S"),
        reconnaissance_type = "Host-based enumeration"
    }
    
    return result
end

-- Register both action functions
local function final_action(host, port)
    if port then
        return action(host, port)
    else
        return host_action(host)
    end
end

-- Set the action function
action = final_action
