<div align="center">
  <img src="https://raw.githubusercontent.com/Larry-Orton/WireWolf/refs/heads/main/WireWolf%20Logo.webp" alt="WireWolf Logo" width="300">
</div>

# WireWolf

**WireWolf** is a fast and powerful network scanning tool for cybersecurity professionals. It provides detailed insights about IPs and domains, including open ports, GeoIP location, and more. The tool is optimized for simplicity and efficiency, making it an essential addition to your toolkit.

---

## Features

- **Port Scanning**: Quickly identifies open ports on a target.
- **GeoIP Lookup**: Retrieves geographic details of the target IP.
- **Fast Mode**: Provides essential results with minimal scan time.
- **Customizable Scans**: Specify ports to scan for targeted results.
- **Simple Installation**: Easy to install and update using `pipx`.

---

## Installation

The easiest way to install and manage **WireWolf** is using `pipx`. This ensures an isolated and conflict-free environment for your tool.

### 1. Install `pipx`

First, install `pipx` if it's not already available on your system:

#### For Debian-Based Systems (e.g., Kali Linux, Ubuntu):
```bash
sudo apt update
sudo apt install pipx
pipx ensurepath
```
## Install WireWolf
Use pipx to install WireWolf from the GitHub repository:
```bash
pipx install git+https://github.com/larry-orton/WireWolf.git
```
## Usage
After installation, you can use the ``` wirewolf``` command directly from your terminal.

Basic Syntax:
wirewolf -t <target>
<target> can be an IP address or domain.
## Command-Line Options
Option	Description
| Option           | Description                                                                 |
|------------------|-----------------------------------------------------------------------------|
| `-t`, `--target` | Target domain or IP to scan.                                                |
| `-o`, `--output` | Save the scan results to a specified file.                                  |
| `-p`, `--ports`  | Specify ports to scan (e.g., `80,443,8080`) or ranges (e.g., `1-1000`).     |
| `-v`, `--verbose`| Enable verbose output for detailed scanning progress.                       |
| `-h`, `--help`   | Display help information and usage details.                                 |

## Examples:
Basic Scan:
```bash
wirewolf -t example.com
```
Fast Mode:
```bash
wirewolf -t example.com --fast
```
Scan Specific Ports:
```bash
wirewolf -t example.com -p 80,443
```
Scan a Range of Ports:
```bash
wirewolf -t example.com -p 1-1000
```
## Example Output
```shell
==========================
 WireWolf Network Scanner
==========================

Target: example.com (93.184.216.34)
Scan Date: 2024-11-19
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
    - 80/tcp: HTTP (Apache 2.4.41)
    - 443/tcp: HTTPS (nginx 1.21.3)

[+] Operating System:
    - Detected: Linux (Kernel 5.x)

[+] Website Metadata:
    - Title: Example Domain
    - Server: ECS (nyb/1.19.3)
    - SSL Details:
        - Issuer: DigiCert Inc
        - Valid From: 2023-11-01
        - Expiry: 2025-11-01

[+] Whois Information:
    - ASN: 15133
    - Network: EDGECAST INC
    - Registrar: ARIN
    - Org: EdgeCast Networks, Inc.

--------------------------------
Scan Complete. Total time: 5.23s
```
## How It Works
WireWolf leverages several Python libraries and tools to deliver comprehensive results:

nmap: For open port and service detection.
geoip2: To provide geographic details of IP addresses.
requests: For fetching website metadata.
ipwhois: To gather organizational and registration data of IPs.
Contributing
We welcome contributions! If you find a bug or want to add features:

Fork this repository.
Create a new branch (feature-branch).
Submit a pull request.
License
WireWolf is licensed under the MIT License.


