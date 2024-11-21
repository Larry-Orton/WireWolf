<div align="center">
  <img src="https://raw.githubusercontent.com/Larry-Orton/WireWolf/refs/heads/main/WireWolf%20Logo.webp" alt="WireWolf Logo" width="300">
</div>

# WireWolf - Network Scanner Tool 🐺

## Overview

**WireWolf** is a fast, modern, and feature-rich network scanner designed for cybersecurity professionals. With **WireWolf**, you can perform detailed scans on domains or IPs to gather essential information such as:

- Open ports
- GeoIP location
- Operating system
- Website metadata
- WHOIS information

WireWolf offers both a **full scan mode** and a **fast mode** for streamlined results.

---

## Features

- **Target Scanning**: Perform detailed scans of IPs and domains.
- **GeoIP Lookup**: Get geographic information (e.g., country, region, city).
- **Port Scanning**: Detect open ports and their services.
- **Website Metadata**: Gather HTTP server details and SSL info.
- **WHOIS Lookup**: Retrieve registration and ownership details.
- **Fast Mode**: Quickly scan basic details like GeoIP and common ports (80, 443).
- **Interactive Shell**: Use the intuitive `WireWolf>` shell for seamless scanning.

---

## Installation

### **Using pipx**

The easiest way to install and manage **WireWolf** is via `pipx`:

```bash
sudo apt install pipx
pipx ensurepath
```
## Install WireWolf:

```bash
pipx install git+https://github.com/larry-orton/WireWolf.git
```
## Run WireWolf:

```bash
wirewolf
```

# Usage
Run WireWolf to enter the interactive shell:

```bash
wirewolf
```
## You will see the following banner:

```bash
=============================================
 __        __  _                                 
 \ \      / / | |                            
  \ \ /\ / /__| | ___ ___  _ __ ___   ___  
   \ V  V / _ \ |/ __/ _ \| '_ ` _ \ / _ \ 
    \_/\_/  __/ | (_| (_) | | | | | |  __/ 
         \___|_|\___\___/|_| |_| |_|\___|  
                                                   
        WireWolf - Network Scanner Tool            
          Version: 1.0.0                           
          Author: Larry Orton                      
=============================================

Type `help` for available commands.
🐺 WireWolf>
```
Command-Line Options
| Option            | Argument         | Description                                                                |
|-------------------|------------------|----------------------------------------------------------------------------|
| `-t`, `--target`  | `<IP/Domain>`    | Specify the target domain or IP to scan. **(Required)**                   |
| `-o`, `--output`  | `<File>`         | Save the scan results to the specified file.                              |
| `-p`, `--ports`   | `<Ports>`        | Ports to scan (e.g., "80,443" or "1-1000"). Default: `80,443`.            |
| `-f`, `--fast`    | None             | Enable fast mode: scan only IP, GeoIP, and two common ports (80, 443).    |
| `-v`, `--verbose` | None             | Enable detailed output during scanning.                                   |
| `-h`, `--help`    | None             | Display help information and usage details.                               |


## Examples
1. Basic Scan
Scan the target example.com with default ports (80,443):

```bash
scan -t example.com
```

2. Custom Ports
Scan the target example.com with custom ports:

```bash
scan -t example.com -p 22,8080
```

3. Save Report
Scan the target and save the report to report.txt:

```bash
scan -t example.com -o report.txt
```
4. Fast Scan
Perform a quick scan with only basic details (GeoIP and ports 80,443):

```bash
scan -t example.com -f
```
5. Verbose Output
Enable verbose mode for detailed scanning progress:

```bash
scan -t example.com -v
```
# Report Format
When the scan completes, WireWolf will generate a detailed report like this:
```bash
==========================
 WireWolf Network Scanner
==========================

Target: example.com (93.184.216.34)
Scan Date: 2024-11-20
================================

[+] Resolved IP Address:
    - 93.184.216.34

[+] GeoIP Information:
    - Country: United States
    - Region: California
    - City: Los Angeles
    - Latitude: 34.0522
    - Longitude: -118.2437

[+] Open Ports:
    - 80/tcp: open (HTTP)
    - 443/tcp: open (HTTPS)

[+] Website Metadata:
    - Status Code: 200
    - Server: Apache/2.4.41
    - Content-Type: text/html; charset=UTF-8

[+] Whois Information:
    - ASN: 15133
    - Network: EDGECAST INC
    - Org: EdgeCast Networks, Inc.

--------------------------------
Scan Complete.
```
For fast mode (--fast), the report will include only:

Resolved IP
GeoIP information
Common ports (80, 443)

# Updating WireWolf
If you installed WireWolf using pipx, you can easily update it by running:
```bash
pipx reinstall WireWolf
```

# License
This project is licensed under the MIT License.

# Author
Larry Orton





