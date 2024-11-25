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

VERSION = "1.2.1"
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
        "          Version: 1.2.1                           \n"
        "          Author: Larry Orton                      \n"
        "=============================================\n\n"
        "Type `help` for available commands."
        "\n"
    )

    def do_update(self, args):
    """Update WireWolf to the latest version."""
    print("[+] Checking for updates...")
    try:
        subprocess.run(["pipx", "reinstall", "WireWolf"], check=True)
        print("[+] WireWolf updated successfully! 🚀")
    except subprocess.CalledProcessError as e:
        print("[!] Update failed. Please ensure pipx is installed and configured correctly.")
        print(f"[!] Error: {e}")


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

        parser.add_argument('-t', '--target', required=True, help='Target IP or domain to scan (required).')
        parser.add_argument('-p', '--ports', default='80,443', help='Specify ports to scan. (Default: 80,443)')
        parser.add_argument('-o', '--output', help='Save the scan results to a specified file.')
        parser.add_argument('-f', '--fast', action='store_true', help='Enable fast mode: Scan basic details only.')
        parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output.')
        parser.add_argument('--subdomains', action='store_true', help='Enumerate subdomains for the target domain.')
        parser.add_argument('--traceroute', action='store_true', help='Perform a traceroute to the target')
        parser.add_argument('--dns', action='store_true', help='Retrieve DNS records for the target domain.')
        parser.add_argument('--vulnerabilities', action='store_true', help='Scan for vulnerabilities based on detected services.')
        parser.add_argument('-h', '--help', action='help', help='Show this help menu.')

        try:
            args = parser.parse_args(args.split())
            # Call the scanning function with parsed arguments
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
                args.vulnerabilities
            )
        except SystemExit:
            print("""
=============================================
          SCAN COMMAND HELP MENU            
=============================================

🔎 **SCAN COMMAND USAGE**
---------------------------------------------
🐺 `scan -t <target> [options]`

📝 **OPTIONS**
---------------------------------------------
-t, --target        Target IP or domain to scan (Required).
-p, --ports         Ports to scan (e.g., "80,443" or "1-1000"). Default: 80,443.
-o, --output        Save the scan results to the specified file.
-f, --fast          Enable fast mode: Scan basic details only (IP, GeoIP, ports 80,443).
-v, --verbose       Enable detailed output during the scan.
--subdomains        Enumerate subdomains for the target domain.
--traceroute        Perform a traceroute to the target IP.
--dns               Retrieve DNS records (A, MX) for the target domain.
--vulnerabilities   Scan for vulnerabilities based on detected services.
-h, --help          Display this help menu.

🚀 **EXAMPLES**
---------------------------------------------
1️⃣ Basic Scan:
   🐺 `scan -t example.com`

2️⃣ Scan Custom Ports:
   🐺 `scan -t example.com -p 22,8080`

3️⃣ Save Report to File:
   🐺 `scan -t example.com -o results.txt`

4️⃣ Enable Fast Mode:
   🐺 `scan -t example.com -f`

5️⃣ Find Subdomains:
   🐺 `scan -t example.com --subdomains`

6️⃣ Perform Traceroute:
   🐺 `scan -t 8.8.8.8 --traceroute`

7️⃣ Lookup DNS Records:
   🐺 `scan -t example.com --dns`

8️⃣ Scan for Vulnerabilities:
   🐺 `scan -t example.com --vulnerabilities`

✨ **TIP**: Combine options for a comprehensive scan:
   🐺 `scan -t example.com --dns --vulnerabilities --subdomains`
=============================================
        """)

    def do_exit(self, args):
        """Exit the WireWolf shell."""
        print("Goodbye!")
        return True


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


def perform_scan(target, ports, output_file, verbose, fast, subdomains, traceroute, dns_lookup, vulnerabilities):
    """Perform the full or fast scan based on user input."""
    ip = socket.gethostbyname(target)

    if fast:
        # Fast mode: Only IP resolution, GeoIP, and two common ports
        geo_data = get_geoip(ip)
        port_data = scan_ports(ip, '80,443', verbose)
        generate_report(target, ip, geo_data, port_data, [], [], {}, [], output_file)
    else:
        # Full scan
        geo_data = get_geoip(ip)
        port_data = scan_ports(ip, ports, verbose)
        subdomains_data = enumerate_subdomains(target) if subdomains else []
        traceroute_data = trace_route(ip) if traceroute else []
        dns_data = lookup_dns(target) if dns_lookup else {}
        vulnerabilities_data = scan_vulnerabilities(port_data) if vulnerabilities else []

        generate_report(
            target, ip, geo_data, port_data, subdomains_data,
            traceroute_data, dns_data, vulnerabilities_data, output_file
        )


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


# Generate Scan Report
def generate_report(target, ip, geo_data, ports, subdomains, traceroute, dns_data, vulnerabilities, output_file):
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
        *[f"    {vuln['port']}/tcp: {vuln['cve']} - {vuln['description']}" for vuln in vulnerabilities]
    ]
    print("\n".join(report))


def main():
    """Main entry point for WireWolf."""
    WireWolfShell().cmdloop()


if __name__ == "__main__":
    main()
