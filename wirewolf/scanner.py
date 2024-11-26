import argparse
import nmap
import socket
import requests
from ipwhois import IPWhois
from datetime import datetime
from cmd import Cmd
import itertools
import sys
import threading
import time
import dns.resolver
import subprocess
from OpenSSL import crypto

VERSION = "1.4.0"
AUTHOR = "Larry Orton"

# Global flag for spinner
stop_spinner = False

# Dependency check function
import subprocess
import sys

import subprocess
import sys
import os

def check_dependencies():
    """Ensure all required dependencies are installed via pipx."""
    required_packages = {
        "nmap": "nmap",
        "dns": "dnspython",
        "requests": "requests",
        "OpenSSL": "pyOpenSSL"
    }

    print("[+] Checking for required dependencies...")

    # Ensure pipx is installed and configured
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--user", "pipx"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        subprocess.run(
            ["pipx", "ensurepath"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        print("[+] pipx is installed and configured.")
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to install pipx. Error: {e}")
        sys.exit("[!] Please install pipx manually to continue.")

    # Check and install dependencies
    for module_name, package_name in required_packages.items():
        try:
            __import__(module_name)
            print(f"[+] Dependency '{module_name}' is already installed.")
        except ImportError:
            print(f"[!] Missing dependency: {module_name} (installing {package_name} via pipx)...")
            try:
                subprocess.run(
                    ["pipx", "install", package_name],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                print(f"[+] Successfully installed: {package_name}.")
            except subprocess.CalledProcessError as e:
                print(f"[!] Failed to install {package_name}. Error: {e}")
                sys.exit(f"[!] WireWolf cannot run without {package_name}. Please install it manually.")

    # Test importing OpenSSL to confirm it's installed
    try:
        from OpenSSL import crypto
        print("[+] OpenSSL is correctly installed.")
    except ImportError:
        print("[!] OpenSSL installation failed.")
        sys.exit("[!] Please verify the installation of OpenSSL and try again.")

    print("[+] All dependencies are installed and verified.")




# Spinner for scan progress
def spinner(message):
    """Display an animated spinner with a message."""
    global stop_spinner
    spinner_chars = itertools.cycle(["|", "/", "-", "\\"])
    sys.stdout.write(f"\r{message} ")
    while not stop_spinner:
        sys.stdout.write(next(spinner_chars))
        sys.stdout.flush()
        time.sleep(0.1)
        sys.stdout.write("\b")

# Function to run tasks with spinner
def run_with_spinner(task_function, *args):
    """Run a task with a loading spinner."""
    global stop_spinner
    stop_spinner = False
    spinner_thread = threading.Thread(target=spinner, args=("Running scan...",))
    spinner_thread.daemon = True
    spinner_thread.start()
    try:
        task_function(*args)
    finally:
        stop_spinner = True
        spinner_thread.join()
        sys.stdout.write("\r" + " " * 30 + "\r")  # Clear spinner
        sys.stdout.flush()

# Main shell for WireWolf
class WireWolfShell(Cmd):
    """Interactive shell for WireWolf."""
    prompt = "🐺 WireWolf> "
    intro = (
        f"=============================================\n"
        f" __        __  _                              \n"
        f" \\ \\      / / | |                             \n"
        f"  \\ \\ /\\ / /__| | ___ ___  _ __ ___   ___     \n"
        f"   \\ V  V / _ \\ |/ __/ _ \\| '_ ` _ \\ / _ \\   \n"
        f"    \\_/\\_/  __/ | (_| (_) | | | | | |  __/ | \n"
        f"         \\___|_|\\___\\___/|_| |_| |_|\\___|  \n"
        f"                                             \n"
        f"        WireWolf - Network Scanner Tool       \n"
        f"          Version: {VERSION}                 \n"
        f"          Author: {AUTHOR}                   \n"
        f"=============================================\n\n"
        f"Type `menu` for a guided experience or `help` for command usage.\n"
    )

    def do_menu(self, args):
        """Display a guided menu."""
        print("""
=============================================
🛠️  WireWolf - Guided Menu 🛠️
=============================================
1️⃣  Basic Scan
    Perform a basic scan of a target IP or domain.

2️⃣  Advanced Scan
    Perform scans with options like subdomains, traceroute, vulnerabilities, etc.

3️⃣  Update WireWolf
    Update the tool to the latest version.

4️⃣  Exit
    Quit the WireWolf shell.
=============================================
        """)
        choice = input("Select an option (1-4): ").strip()
        if choice == "1":
            target = input("Enter target (IP or domain): ").strip()
            self.do_scan(f"-t {target}")
        elif choice == "2":
            print("[!] Use `scan -h` to explore advanced options.")
        elif choice == "3":
            self.do_update("")
        elif choice == "4":
            self.do_exit("")
        else:
            print("[!] Invalid selection. Returning to menu.")

    def do_scan(self, args):
        """Scan a target. Usage: scan -t <target> [options]"""
        parser = argparse.ArgumentParser(
            prog="scan",
            description=(
                "WireWolf Network Scanner - Perform detailed network scans with options for "
                "GeoIP lookup, subdomains, DNS records, vulnerabilities, and more."
            ),
            formatter_class=argparse.RawTextHelpFormatter,
            add_help=False,
        )

        # Define arguments
        parser.add_argument('-t', '--target', required=True, help='Target IP or domain to scan (required).')
        parser.add_argument('-p', '--ports', default='80,443', help='Specify ports to scan. (Default: 80,443)')
        parser.add_argument('-o', '--output', help='Save the scan results to a specified file.')
        parser.add_argument('-f', '--fast', action='store_true', help='Enable fast mode: Scan basic details only.')
        parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output.')
        parser.add_argument('--subdomains', action='store_true', help='Enumerate subdomains for the target domain.')
        parser.add_argument('--traceroute', action='store_true', help='Perform a traceroute to the target.')
        parser.add_argument('--dns', action='store_true', help='Retrieve DNS records for the target domain.')
        parser.add_argument('--vulnerabilities', action='store_true', help='Scan for vulnerabilities.')
        parser.add_argument('--ssl-check', action='store_true', help='Check SSL/TLS configuration.')
        parser.add_argument('--passwords', action='store_true', help='Test password strength.')
        parser.add_argument('--sensitive-files', action='store_true', help='Search for sensitive files.')
        parser.add_argument('-h', '--help', action='store_true', help='Show this help menu.')

        try:
            # Parse arguments
            parsed_args = parser.parse_args(args.split())

            # If help is requested, print the custom help and exit
            if parsed_args.help:
                print(parser.description)
                return

            # Execute the scan with spinner
            run_with_spinner(
                perform_scan,
                parsed_args.target,
                parsed_args.ports,
                parsed_args.output,
                parsed_args.verbose,
                parsed_args.fast,
                parsed_args.subdomains,
                parsed_args.traceroute,
                parsed_args.dns,
                parsed_args.vulnerabilities,
                parsed_args.ssl_check,
                parsed_args.passwords,
                parsed_args.sensitive_files,
            )
        except SystemExit:
            # Show custom help menu in case of invalid usage
            print("[!] Invalid command. Use `scan -h` for help.")
    # Perform Scan Logic
def perform_scan(target, ports, output_file, verbose, fast, subdomains, traceroute, dns_lookup, vulnerabilities, ssl_check, passwords, sensitive_files):
    """Perform the full or fast scan based on user input."""
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[!] Error: Unable to resolve target '{target}'. Please check the domain name or IP address.")
        return

    print(f"[+] Resolved IP: {ip}")

    geo_data = {}
    port_data = []
    subdomains_data = []
    traceroute_data = []
    dns_data = {}
    vulnerabilities_data = []
    ssl_check_data = []
    sensitive_files_data = []

    if fast:
        geo_data = get_geoip(ip)
        port_data = scan_ports(ip, '80,443', verbose)
    else:
        geo_data = get_geoip(ip)
        port_data = scan_ports(ip, ports, verbose)
        if subdomains:
            subdomains_data = enumerate_subdomains(target)
        if traceroute:
            traceroute_data = trace_route(ip)
        if dns_lookup:
            dns_data = lookup_dns(target)
        if vulnerabilities:
            vulnerabilities_data = scan_vulnerabilities(port_data)
        if ssl_check:
            ssl_check_data = check_ssl(target)
        if sensitive_files:
            sensitive_files_data = scan_sensitive_files(target)

    generate_report(
        target, ip, geo_data, port_data, subdomains_data,
        traceroute_data, dns_data, vulnerabilities_data,
        ssl_check_data, sensitive_files_data, output_file
    )


# SSL Check
def check_ssl(target):
    """Check SSL/TLS configuration for the given domain or IP."""
    try:
        context = socket.create_default_context()
        with socket.create_connection((target, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                return {
                    "subject": dict(x[0] for x in cert["subject"]),
                    "issuer": dict(x[0] for x in cert["issuer"]),
                    "version": cert.get("version", "unknown"),
                    "serialNumber": cert.get("serialNumber", "unknown"),
                    "notBefore": cert.get("notBefore", "unknown"),
                    "notAfter": cert.get("notAfter", "unknown"),
                    "subjectAltName": cert.get("subjectAltName", []),
                }
    except Exception as e:
        return {"error": str(e)}


# Sensitive Files Scan
def scan_sensitive_files(target):
    """Check for sensitive files on the target server."""
    sensitive_files = ["robots.txt", ".env", ".git/config", "config.php"]
    found_files = []
    try:
        for file in sensitive_files:
            url = f"http://{target}/{file}"
            response = requests.head(url)
            if response.status_code == 200:
                found_files.append(file)
    except Exception as e:
        print(f"[!] Sensitive file check failed: {e}")
    return found_files


# GeoIP Lookup
def get_geoip(ip):
    """Retrieve geographic information for the given IP."""
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        return response.json() if response.status_code == 200 else {}
    except Exception as e:
        print(f"[!] GeoIP lookup failed: {e}")
        return {}


# Port Scanning
def scan_ports(ip, ports, verbose):
    """Scan specified ports using Nmap."""
    results = []
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, ports, '-T4')
        for port in map(int, ports.split(',')):
            state = nm[ip]['tcp'][port]['state'] if port in nm[ip]['tcp'] else "unknown"
            service = nm[ip]['tcp'][port].get('name', 'unknown') if port in nm[ip]['tcp'] else "unknown"
            results.append((port, state, service))
    except Exception as e:
        print(f"[!] Port scanning failed: {e}")
    return results


# DNS Lookup
def lookup_dns(domain):
    """Retrieve DNS records."""
    records = {}
    try:
        records["A"] = [rdata.to_text() for rdata in dns.resolver.resolve(domain, "A")]
        records["MX"] = [rdata.to_text() for rdata in dns.resolver.resolve(domain, "MX")]
    except Exception as e:
        print(f"[!] DNS lookup failed: {e}")
    return records


# Subdomain Enumeration
def enumerate_subdomains(domain):
    """Enumerate subdomains."""
    subdomains = []
    try:
        subdomain_list = [f"www.{domain}", f"mail.{domain}", f"api.{domain}"]
        for sub in subdomain_list:
            try:
                socket.gethostbyname(sub)
                subdomains.append(sub)
            except socket.gaierror:
                pass
    except Exception as e:
        print(f"[!] Subdomain enumeration failed: {e}")
    return subdomains


# Vulnerability Scanning
def scan_vulnerabilities(ports):
    """Scan for vulnerabilities."""
    vulnerabilities = []
    try:
        for port, state, service in ports:
            if service != "unknown":
                response = requests.get(f"https://cve.circl.lu/api/search/{service}")
                if response.status_code == 200:
                    results = response.json()
                    for cve in results.get("results", []):
                        vulnerabilities.append({
                            "port": port,
                            "cve": cve.get("id", "Unknown"),
                            "description": cve.get("summary", "No description available")
                        })
    except Exception as e:
        print(f"[!] Vulnerability scan failed: {e}")
    return vulnerabilities


# Generate Report
def generate_report(target, ip, geo_data, ports, subdomains, traceroute, dns_data, vulnerabilities, ssl_check, sensitive_files, output_file):
    """Generate the scan report."""
    report = [
        f"Target: {target} ({ip})",
        f"Scan Date: {datetime.now()}",
        "\n[+] GeoIP Information:",
        f"    Country: {geo_data.get('country', 'unknown')}",
        f"    Region: {geo_data.get('regionName', 'unknown')}",
        f"    City: {geo_data.get('city', 'unknown')}",
        "\n[+] Open Ports:",
        *[f"    {port}/tcp: {state} ({service})" for port, state, service in ports],
        "\n[+] DNS Records:",
        *[f"    {key}: {value}" for key, value in dns_data.items()],
        "\n[+] Subdomains:",
        *subdomains,
        "\n[+] Vulnerabilities:",
        *[f"    {vuln['port']}/tcp: {vuln['cve']} - {vuln['description']}" for vuln in vulnerabilities],
        "\n[+] SSL/TLS Configuration:",
        f"    {ssl_check if ssl_check else 'No SSL/TLS issues detected.'}",
        "\n[+] Sensitive Files Found:",
        *sensitive_files,
    ]

    print("\n".join(report))
    if output_file:
        try:
            with open(output_file, 'w') as file:
                file.write("\n".join(report))
            print(f"[+] Report saved to {output_file}")
        except Exception as e:
            print(f"[!] Failed to save report: {e}")


# Main entry point
def main():
    """Main entry point for WireWolf."""
    check_dependencies()  # Ensure all dependencies are installed
    WireWolfShell().cmdloop()


if __name__ == "__main__":
    main()
