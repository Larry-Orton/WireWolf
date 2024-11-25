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
import ssl

VERSION = "1.3.0"
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
        "          Version: 1.3.0                           \n"
        "          Author: Larry Orton                      \n"
        "=============================================\n\n"
        "Type `menu` for a guided experience or `help` for command usage."
        "\n"
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
            description="""=============================================
🔍 WireWolf - Scan Command Help
=============================================

USAGE:
    scan -t <target> [OPTIONS]

OPTIONS:
    -t, --target          Target IP or domain (Required)
    -p, --ports           Ports to scan (Default: 80,443)
    -o, --output          Save scan results to a file
    -f, --fast            Fast mode: Scan IP, GeoIP, and common ports
    -v, --verbose         Show detailed progress during scan
    --subdomains          Enumerate subdomains for the target domain
    --traceroute          Perform a traceroute to the target
    --dns                 Fetch DNS records (A, MX)
    --vulnerabilities     Scan for vulnerabilities
    --ssl-check           Check SSL/TLS configuration
    --passwords           Test password strength
    --sensitive-files     Search for sensitive files
    -h, --help            Show this help menu

EXAMPLES:
    1️⃣  Basic Scan:
        scan -t example.com

    2️⃣  Custom Ports:
        scan -t example.com -p 22,8080

    3️⃣  Save Results:
        scan -t example.com -o results.txt

    4️⃣  Advanced Scan:
        scan -t example.com --subdomains --vulnerabilities

    5️⃣  Fast Mode:
        scan -t example.com -f

TIPS:
    🔹 Combine options for a comprehensive scan
=============================================
            """,
            formatter_class=argparse.RawTextHelpFormatter,
            add_help=False,
        )

        # Define arguments
        parser.add_argument('-t', '--target', help='Target IP or domain to scan (required).')
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

            # Handle `-h` explicitly
            if parsed_args.help:
                print(parser.description)
                return

            # Check if required arguments are missing
            if not parsed_args.target:
                print("[!] Error: The `-t/--target` argument is required for scans.")
                print("[!] Use `scan -h` for help.")
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

    def do_update(self, args):
        """Update WireWolf to the latest version."""
        print("[+] Checking for updates...")
        try:
            subprocess.run(["pipx", "reinstall", "WireWolf"], check=True)
            print("[+] WireWolf updated successfully! 🚀")
        except subprocess.CalledProcessError as e:
            print("[!] Update failed. Please ensure pipx is installed and configured correctly.")
            print(f"[!] Error: {e}")

    def do_exit(self, args):
        """Exit the WireWolf shell."""
        print("Goodbye!")
        return True


# Spinner for Scan Progress
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


def perform_scan(target, ports, output_file, verbose, fast, subdomains, traceroute, dns_lookup, vulnerabilities, ssl_check):
    """Perform the full or fast scan based on user input."""
    try:
        # Resolve target to IP address
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[!] Error: Unable to resolve target '{target}'. Please check the domain name or IP address.")
        return

    print(f"[+] Resolved IP: {ip}")

    # Fast mode
    if fast:
        geo_data = get_geoip(ip)
        port_data = scan_ports(ip, '80,443', verbose)
        generate_report(target, ip, geo_data, port_data, [], [], {}, [], output_file)
        return

    # Full scan logic
    geo_data = get_geoip(ip)
    port_data = scan_ports(ip, ports, verbose)
    subdomains_data = enumerate_subdomains(target) if subdomains else []
    traceroute_data = trace_route(ip) if traceroute else []
    dns_data = lookup_dns(target) if dns_lookup else {}
    vulnerabilities_data = scan_vulnerabilities(port_data) if vulnerabilities else []

    # SSL Check logic
    ssl_check_data = None
    if ssl_check:
        ssl_check_data = check_ssl(ip)
        if ssl_check_data and ssl_check_data["status"] == "error" and "IP address mismatch" in ssl_check_data["message"]:
            print("[!] SSL/TLS Error: IP address mismatch. Retrying with domain...")
            domain_ssl_data = check_ssl(target)  # Retry with the domain name
            ssl_check_data = domain_ssl_data if domain_ssl_data else ssl_check_data

    # Generate and print report
    generate_report(
        target, ip, geo_data, port_data, subdomains_data,
        traceroute_data, dns_data, vulnerabilities_data,
        ssl_check_data, output_file
    )

def get_geoip(ip):
    """Retrieve geographic information for the given IP."""
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        return response.json() if response.status_code == 200 else {}
    except Exception as e:
        print(f"[!] GeoIP lookup failed: {e}")
        return {}


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


def lookup_dns(domain):
    """Retrieve DNS records."""
    records = {}
    try:
        records["A"] = [rdata.to_text() for rdata in dns.resolver.resolve(domain, "A")]
        records["MX"] = [rdata.to_text() for rdata in dns.resolver.resolve(domain, "MX")]
    except Exception as e:
        print(f"[!] DNS lookup failed: {e}")
    return records


def enumerate_subdomains(domain):
    """Enumerate subdomains."""
    subdomains = []
    try:
        subdomain_list = [f"www.{domain}", f"mail.{domain}"]
        for sub in subdomain_list:
            try:
                socket.gethostbyname(sub)
                subdomains.append(sub)
            except socket.gaierror:
                pass
    except Exception as e:
        print(f"[!] Subdomain enumeration failed: {e}")
    return subdomains


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
    
def check_ssl(target):
    """Check SSL/TLS configuration for a target."""
    try:
        # Attempt to resolve the target as an IP
        context = ssl.create_default_context()
        with socket.create_connection((target, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                return {
                    "status": "success",
                    "certificate": cert,
                }
    except ssl.SSLCertVerificationError as e:
        # Check if the error is due to an IP address mismatch
        if "IP address mismatch" in str(e):
            print(f"[!] SSL/TLS Error for IP: {e}. Trying domain fallback...")
            domain = resolve_domain_from_ip(target)
            if domain:
                return check_ssl(domain)  # Retry with the domain
            else:
                return {"status": "error", "message": "Failed to resolve domain from IP."}
        return {"status": "error", "message": str(e)}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def resolve_domain_from_ip(ip):
    """Attempt to resolve a domain name from an IP address."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        print(f"[!] Unable to resolve domain for IP: {ip}")
        return None

def generate_report(target, ip, geo_data, ports, subdomains, traceroute, dns_data, vulnerabilities, ssl_check, passwords, sensitive_files, output_file):
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
    ]

    if subdomains:
        report.append("\n[+] Subdomains Found:")
        report.extend([f"    - {sub}" for sub in subdomains])

    if traceroute:
        report.append("\n[+] Traceroute Results:")
        report.extend([f"    {hop}" for hop in traceroute])

    if dns_data:
        report.append("\n[+] DNS Records:")
        for record_type, records in dns_data.items():
            report.append(f"    {record_type}:")
            report.extend([f"      - {record}" for record in records])

    if vulnerabilities:
        report.append("\n[+] Vulnerabilities Found:")
        for vuln in vulnerabilities:
            report.append(f"    - {vuln['port']}/tcp: {vuln['cve']} - {vuln['description']}")
    else:
        report.append("\n[+] Vulnerabilities Found: None (No issues detected!)")

    if ssl_check:
        report.append("\n[+] SSL/TLS Configuration:")
        report.extend([f"    {item}" for item in ssl_check])

    if passwords:
        report.append("\n[+] Password Strength:")
        report.extend([f"    {item}" for item in passwords])

    if sensitive_files:
        report.append("\n[+] Sensitive Files:")
        report.extend([f"    {item}" for item in sensitive_files])

    report.append("\n--------------------------------")
    report.append("Scan Complete.")
    print("\n".join(report))

    # Save to file if specified
    if output_file:
        try:
            with open(output_file, 'w') as f:
                f.write("\n".join(report))
            print(f"[+] Report saved to {output_file}")
        except Exception as e:
            print(f"[!] Failed to save report: {e}")



def main():
    """Main entry point for WireWolf."""
    WireWolfShell().cmdloop()


if __name__ == "__main__":
    main()
