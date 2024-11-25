import argparse
import socket
import subprocess
import sys
import threading
import time
import itertools
from datetime import datetime
from cmd import Cmd

# Check and install required packages
def check_and_install_packages():
    required_packages = ["beautifulsoup4", "nmap", "requests", "ipwhois", "dnspython"]
    for package in required_packages:
        try:
            __import__(package.split("-")[0])  # Convert package name to module name
        except ImportError:
            print(f"[!] {package} is not installed. Installing...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                print(f"[+] {package} installed successfully.")
            except Exception as e:
                print(f"[!] Failed to install {package}: {e}")
                sys.exit(1)

# Run the dependency check at startup
check_and_install_packages()

# Import packages after ensuring they are installed
import nmap
import requests
from ipwhois import IPWhois
from bs4 import BeautifulSoup
import dns.resolver

VERSION = "1.7.4"
AUTHOR = "Larry Orton"

# Global flag to stop the spinner
stop_spinner = False


class WireWolfShell(Cmd):
    """Interactive shell for WireWolf."""
    prompt = "🐺 WireWolf> "
    intro = (
        "=============================================\n"
        " __        __  _                                   \n"
        " \\ \\      / / | |                                \n"
        "  \\ \\ /\\ / /__| | ___ ___  _ __ ___   ___       \n"
        "   \\ V  V / _ \\ |/ __/ _ \\| '_ ` _ \\ / _ \\     \n"
        "    \\_/\\_/  __/ | (_| (_) | | | | | |  __/ |     \n"
        "         \\___|_|\\___\\___/|_| |_| |_|\\___|      \n"
        "                                                   \n"
        "        WireWolf - Network Scanner Tool            \n"
        "          Version: 1.7.4                           \n"
        "          Author: Larry Orton                      \n"
        "=============================================\n\n"
        "Type `help` for available commands."
        "\n"
    )

    def do_scan(self, args):
        """Perform a network scan. Type `scan -h` for detailed options."""
        parser = argparse.ArgumentParser(
            prog="scan",
            description=(
                "WireWolf Network Scanner - Perform advanced scans with options for:\n"
                "- GeoIP lookup\n"
                "- Subdomains enumeration\n"
                "- DNS record fetching\n"
                "- Vulnerability analysis\n"
                "- SSL/TLS configuration checks\n"
                "- Sensitive files search\n"
                "- Password brute-force simulations\n"
            ),
            formatter_class=argparse.RawTextHelpFormatter,
            add_help=False,
        )

        parser.add_argument('-t', '--target', required=True, help='Target IP or domain to scan (required).')
        parser.add_argument('-p', '--ports', default='80,443', help='Specify ports to scan (Default: 80,443).')
        parser.add_argument('-o', '--output', help='Save the scan results to a file (HTML format supported).')
        parser.add_argument('-f', '--fast', action='store_true', help='Enable fast mode: Scan basic details only.')
        parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output.')
        parser.add_argument('--subdomains', action='store_true', help='Enumerate subdomains for the target domain.')
        parser.add_argument('--traceroute', action='store_true', help='Perform a traceroute to the target IP.')
        parser.add_argument('--dns', action='store_true', help='Fetch DNS records (A, MX) for the target.')
        parser.add_argument('--vulnerabilities', action='store_true', help='Scan for vulnerabilities.')
        parser.add_argument('--fingerprint', action='store_true', help='Perform web application fingerprinting.')
        parser.add_argument('--ssl-check', action='store_true', help='Check SSL/TLS configurations.')
        parser.add_argument('--passwords', action='store_true', help='Simulate password brute force.')
        parser.add_argument('--sensitive-files', action='store_true', help='Search for sensitive files.')
        parser.add_argument('-h', '--help', action='help', help='Display this help menu.')

        try:
            args = parser.parse_args(args.split())
            run_with_spinner(
                perform_scan,
                args.target,
                args.ports,
                args.output,
                args.verbose,
                args.fast,
                args.subdomains,
                args.traceroute,
                args.dns,
                args.vulnerabilities,
                args.fingerprint,
                args.ssl_check,
                args.passwords,
                args.sensitive_files
            )
        except SystemExit:
            print("""
=============================================
              SCAN COMMAND HELP             
=============================================
📌 Usage: `scan -t <target> [options]`
---------------------------------------------
🎯 Required Options:
-t, --target        Target IP or domain to scan.

🛠️ Additional Options:
-p, --ports         Ports to scan (e.g., 80,443). Default: 80,443.
-o, --output        Save the scan results to a file (HTML supported).
-f, --fast          Enable fast mode: Scan IP, GeoIP, ports 80/443 only.
-v, --verbose       Display detailed scan progress.
--subdomains        Enumerate subdomains for the domain.
--traceroute        Perform a traceroute to the target IP.
--dns               Retrieve DNS records (A, MX).
--vulnerabilities   Scan for vulnerabilities on detected services.
--fingerprint       Perform web application fingerprinting.
--ssl-check         Check SSL/TLS configurations.
--passwords         Simulate password brute force.
--sensitive-files   Check for exposed sensitive files.

📝 Examples:
1️⃣ Basic Scan: `scan -t example.com`
2️⃣ Save Report: `scan -t example.com -o results.html`
3️⃣ Subdomain Scan: `scan -t example.com --subdomains`
4️⃣ Full Scan: `scan -t example.com --dns --vulnerabilities --ssl-check`

=============================================
            """)


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
        sys.stdout.write("\r" + " " * 30 + "\r")  # Clear the spinner line
        sys.stdout.flush()


def perform_scan(target, ports, output_file, verbose, fast, subdomains, traceroute, dns_lookup, vulnerabilities, fingerprint, ssl_check, passwords, sensitive_files):
    """Perform a full or fast scan based on user input."""
    ip = socket.gethostbyname(target)

    if fast:
        geo_data = get_geoip(ip)
        port_data = scan_ports(ip, '80,443', verbose)
        generate_report(target, ip, geo_data, port_data, [], [], {}, [], {}, "", [], "", output_file)
    else:
        geo_data = get_geoip(ip)
        port_data = scan_ports(ip, ports, verbose)
        subdomain_data = enumerate_subdomains(target) if subdomains else []
        traceroute_data = trace_route(ip) if traceroute else []
        dns_data = lookup_dns(target) if dns_lookup else {}
        vulnerabilities_data = scan_vulnerabilities(port_data) if vulnerabilities else []
        fingerprint_data = web_fingerprint(target) if fingerprint else {}
        ssl_data = check_ssl_config(target) if ssl_check else {}
        sensitive_files_data = scan_sensitive_files(target) if sensitive_files else []
        passwords_data = password_strength_check(target) if passwords else []

        generate_report(
            target, ip, geo_data, port_data, subdomain_data,
            traceroute_data, dns_data, vulnerabilities_data,
            fingerprint_data, ssl_data, sensitive_files_data,
            passwords_data, output_file
        )


def generate_report(target, ip, geo_data, ports, subdomains, traceroute, dns_data, vulnerabilities, fingerprint, ssl_config, sensitive_files, passwords, output_file):
    """Generate a detailed scan report."""
    report = [
        "==========================",
        " WireWolf Network Scanner",
        "==========================",
        f"Target: {target} ({ip})",
        f"Scan Date: {datetime.now()}",
        "================================"
    ]

    # GeoIP Information
    report.append("\n[+] GeoIP Information:")
    for key, value in geo_data.items():
        report.append(f"    {key.capitalize()}: {value}")

    # Open Ports
    report.append("\n[+] Open Ports:")
    for port, state, service in ports:
        report.append(f"    {port}/tcp: {state} ({service})")

    # Subdomains
    if subdomains:
        report.append("\n[+] Subdomains Found:")
        for subdomain in subdomains:
            report.append(f"    {subdomain}")

    # Vulnerabilities
    if vulnerabilities:
        report.append("\n[+] Identified Vulnerabilities:")
        for vuln in vulnerabilities:
            report.append(f"    - {vuln['service']} (Port: {vuln['port']}): {vuln['cve']}\n      {vuln['description']}")

    # Sensitive Files
    if sensitive_files:
        report.append("\n[+] Sensitive Files Found:")
        for file in sensitive_files:
            report.append(f"    {file}")

    # SSL Configurations
    if ssl_config:
        report.append("\n[+] SSL/TLS Configuration:")
        for key, value in ssl_config.items():
            report.append(f"    {key.capitalize()}: {value}")

    # Password Brute Force
    if passwords:
        report.append("\n[+] Password Strength:")
        for result in passwords:
            report.append(f"    {result}")

    # Print Report
    print("\n".join(report))


def main():
    """Main entry point for WireWolf."""
    WireWolfShell().cmdloop()


if __name__ == "__main__":
    main()
