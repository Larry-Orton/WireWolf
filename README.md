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
