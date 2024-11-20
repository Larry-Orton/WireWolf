<div align="center">
  <img src="path-to-your-image.png](https://github.com/Larry-Orton/WireWolf/blob/main/WireWolf%20Logo.webp" alt="Your Image Description" width="300">
</div>

# WireWolf

**WireWolf** is a sleek, modern network scanning tool for cybersecurity professionals. It provides a comprehensive analysis of target IPs, domains, and networks directly from the terminal. Built in Python, WireWolf integrates powerful features like port scanning, GeoIP lookup, website metadata analysis, and OS detection in a single, easy-to-use tool.

## Features

- **Fast Scanning**: Asynchronous port scanning for rapid results.
- **GeoIP Information**: Identify the location of the target IP.
- **Open Ports Detection**: Displays all active ports with service information.
- **OS Detection**: Determines the operating system of the target.
- **Website Analysis**: Fetches metadata, SSL details, and server information.
- **Whois Lookup**: Provides organizational details of the target's IP.
- **Clean Terminal Interface**: Outputs data in a clear, well-organized format.

## Installation

### Prerequisites
- Python 3.8 or higher
- `nmap` installed on your system:
  ```bash
  sudo apt-get install nmap

Required Python libraries:
```shell
pip install python-nmap requests geoip2 ipwhois
```
## Steps to Install
Clone the repository:
```shell
git clone https://github.com/yourusername/WireWolf.git
```
Navigate to the directory:
```shell
cd WireWolf
```
Install WireWolf locally:
```shell
pip install .
```
Now you can use wirewolf as a terminal command.

Usage
Basic Command
```shell
wirewolf -t <target>
```
## Examples
Scan a domain:
```shell
wirewolf -t example.com
```
Scan an IP:
```shell
wirewolf -t 93.184.216.34
```
Save output to a file:
```shell
wirewolf -t example.com -o scan_results.txt
```
## Command-Line Options
Option	Description
| Option           | Description                                                                 |
|------------------|-----------------------------------------------------------------------------|
| `-t`, `--target` | Target domain or IP to scan.                                                |
| `-o`, `--output` | Save the scan results to a specified file.                                  |
| `-p`, `--ports`  | Specify ports to scan (e.g., `80,443,8080`) or ranges (e.g., `1-1000`).     |
| `-v`, `--verbose`| Enable verbose output for detailed scanning progress.                       |
| `-h`, `--help`   | Display help information and usage details.                                 |


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


