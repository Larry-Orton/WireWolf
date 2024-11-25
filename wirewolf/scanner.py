import argparse
import socket
import subprocess
import sys
import threading
import time
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

VERSION = "1.5.0"
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
        "          Version: 1.5.0                           \n"
        "          Author: Larry Orton                      \n"
        "=============================================\n\n"
        "Type `help` for available commands."
        "\n"
    )

    def do_scan(self, args):
        """Scan a target. Usage: scan -t <target> [options]"""
        parser = argparse.ArgumentParser(
            prog="scan",
            description=(
                "WireWolf Network Scanner - Perform detailed network scans with options for "
                "GeoIP lookup, subdomains, DNS records, vulnerabilities, web fingerprinting, "
                "TLS checks, and more."
            ),
            formatter_class=argparse.RawTextHelpFormatter,
            add_help=False,
        )

        parser.add_argument('-t', '--target', required=True, help='Target IP or domain to scan (required).')
        parser.add_argument('-p', '--ports', default='80,443', help='Specify ports to scan. (Default: 80,443)')
        parser.add_argument('-o', '--output', help='Save the scan results to a specified file (HTML format supported).')
        parser.add_argument('-f', '--fast', action='store_true', help='Enable fast mode: Scan basic details only.')
        parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output.')
        parser.add_argument('--subdomains', action='store_true', help='Enumerate subdomains for the target domain.')
        parser.add_argument('--traceroute', action='store_true', help='Perform a traceroute to the target IP.')
        parser.add_argument('--dns', action='store_true', help='Retrieve DNS records (A, MX) for the target domain.')
        parser.add_argument('--vulnerabilities', action='store_true', help='Scan for vulnerabilities based on detected services.')
        parser.add_argument('--fingerprint', action='store_true', help='Perform web application fingerprinting.')
        parser.add_argument('--ssl-check', action='store_true', help='Check SSL/TLS configurations for vulnerabilities.')
        parser.add_argument('--passwords', action='store_true', help='Simulate password brute force with a wordlist.')
        parser.add_argument('--sensitive-files', action='store_true', help='Check for exposed sensitive files on the target.')
        parser.add_argument('-h', '--help', action='help', help='Show this help menu.')

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
            print("Run `scan -h` to view the help menu.")


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


# Scan logic for GeoIP, Ports, Subdomains, etc.
def perform_scan(target, ports, output_file, verbose, fast, subdomains, traceroute, dns_lookup, vulnerabilities, fingerprint, ssl_check, passwords, sensitive_files):
    ip = socket.gethostbyname(target)

    if fast:
        geo_data = get_geoip(ip)
        port_data = scan_ports(ip, '80,443', verbose)
        generate_report(target, ip, geo_data, port_data, output_file)
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

        # Combine results and generate report
        generate_report(
            target,
            ip,
            geo_data,
            port_data,
            subdomain_data,
            traceroute_data,
            dns_data,
            vulnerabilities_data,
            fingerprint_data,
            ssl_data,
            sensitive_files_data,
            passwords_data,
            output_file
        )


def get_geoip(ip):
    """Retrieve geographic information for the given IP using ip-api.com."""
    geo_data = {}
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()
        if data['status'] == 'success':
            geo_data = {
                'country': data.get('country', 'Unknown'),
                'region': data.get('regionName', 'Unknown'),
                'city': data.get('city', 'Unknown'),
                'latitude': data.get('lat', 'Unknown'),
                'longitude': data.get('lon', 'Unknown')
            }
    except Exception as e:
        print(f"[!] GeoIP lookup failed: {e}")
    return geo_data


def scan_ports(ip, ports, verbose):
    """Scan specified ports using Nmap."""
    results = []
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, ports, '-T4')
        for port in sorted(map(int, ports.split(','))):
            state = nm[ip]['tcp'][port]['state'] if port in nm[ip]['tcp'] else "unknown"
            service = nm[ip]['tcp'][port].get('name', 'unknown') if port in nm[ip]['tcp'] else "unknown"
            results.append((port, state, service))
    except Exception as e:
        print(f"[!] An error occurred during port scanning: {e}")
    return results


def enumerate_subdomains(domain):
    """Enumerate subdomains for a given domain."""
    subdomains = []
    try:
        common_subdomains = [f"www.{domain}", f"api.{domain}", f"mail.{domain}"]
        for sub in common_subdomains:
            try:
                socket.gethostbyname(sub)
                subdomains.append(sub)
            except socket.gaierror:
                pass
    except Exception as e:
        print(f"[!] Subdomain enumeration failed: {e}")
    return subdomains


def trace_route(ip):
    """Perform a traceroute to the target IP."""
    traceroute_output = []
    try:
        result = subprocess.run(["traceroute", ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        traceroute_output = result.stdout.decode().splitlines()
    except Exception as e:
        print(f"[!] Traceroute failed: {e}")
    return traceroute_output


def lookup_dns(domain):
    """Retrieve DNS records for the domain."""
    dns_data = {}
    try:
        dns_data["A"] = [rdata.to_text() for rdata in dns.resolver.resolve(domain, "A")]
        dns_data["MX"] = [rdata.to_text() for rdata in dns.resolver.resolve(domain, "MX")]
    except Exception as e:
        print(f"[!] DNS lookup failed: {e}")
    return dns_data


def scan_vulnerabilities(ports):
    """Simulate a vulnerability scan."""
    vulnerabilities = []
    for port, state, service in ports:
        if service != "unknown":
            vulnerabilities.append({
                "service": service,
                "port": port,
                "description": "Simulated vulnerability description.",
                "severity": "Medium"
            })
    return vulnerabilities


def web_fingerprint(target):
    """Perform web application fingerprinting."""
    try:
        response = requests.get(f"http://{target}", timeout=5)
        headers = response.headers
        return headers
    except Exception as e:
        print(f"[!] Web fingerprinting failed: {e}")
    return {}


def check_ssl_config(target):
    """Check SSL/TLS configurations."""
    try:
        result = subprocess.run(
            ["openssl", "s_client", "-connect", f"{target}:443"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10
        )
        return result.stdout.decode()
    except Exception as e:
        print(f"[!] SSL check failed: {e}")
    return "Error performing SSL check."


def scan_sensitive_files(target):
    """Check for sensitive files."""
    print("[+] Scanning for sensitive files...")
    files = [".env", ".git", "backup.zip"]
    exposed_files = []
    try:
        for file in files:
            response = requests.get(f"http://{target}/{file}", timeout=5)
            if response.status_code == 200:
                exposed_files.append(file)
    except Exception as e:
        print(f"[!] Sensitive file check failed: {e}")
    return exposed_files


def password_strength_check(target):
    """Simulate password brute force."""
    print("[+] Simulating password brute force...")
    wordlist = ["admin", "password123", "qwerty"]
    for password in wordlist:
        try:
            response = requests.post(f"http://{target}/login", data={"password": password}, timeout=5)
            if response.status_code == 200:
                return {"Weak Password": password}
        except Exception:
            pass
    return "No weak passwords detected."


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

    report.append("\n[+] GeoIP Information:")
    for key, value in geo_data.items():
        report.append(f"    {key.capitalize()}: {value}")

    report.append("\n[+] Open Ports:")
    for port, state, service in ports:
        report.append(f"    {port}/tcp: {state} ({service})")

    report.append("\n[+] Vulnerabilities:")
    for vuln in vulnerabilities:
        report.append(f"    Port {vuln['port']} - {vuln['service']}: {vuln['description']} (Severity: {vuln['severity']})")

    report.append("\n[+] SSL Configuration:")
    report.append(ssl_config or "No SSL information available.")

    report.append("\n[+] Sensitive Files:")
    if sensitive_files:
        report.extend(f"    {file}" for file in sensitive_files)
    else:
        report.append("    None found.")

    report.append("\n[+] Password Analysis:")
    report.append(passwords if passwords else "    No weak passwords detected.")

    if output_file:
        with open(output_file, 'w') as file:
            file.write("\n".join(report))
        print(f"[+] Report saved to {output_file}")

    print("\n".join(report))


def main():
    """Main entry point for WireWolf."""
    WireWolfShell().cmdloop()


if __name__ == "__main__":
    main()
