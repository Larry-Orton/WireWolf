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
        "Type `menu` to see guided options or `help` for detailed command guidance."
        "\n"
    )

    def do_menu(self, args):
        """Display the guided menu."""
        while True:
            print("""
=============================================
🐺  Welcome to WireWolf Network Scanner 🐺
=============================================

Choose an option:
---------------------------------------------
1️⃣  Scan a Target:
    Perform a detailed network scan on an IP or domain.

2️⃣  Update WireWolf:
    Get the latest version of WireWolf.

3️⃣  Help Menu:
    Learn more about WireWolf's features and commands.

4️⃣  Exit:
    Quit WireWolf.

Type the number or name of the command to proceed:
            """)
            choice = input("> ").strip().lower()

            if choice in ["1", "scan"]:
                print("\n🔎 Starting Scan...\n")
                self.cmdloop()
            elif choice in ["2", "update"]:
                self.do_update("")
            elif choice in ["3", "help"]:
                self.do_help("")
            elif choice in ["4", "exit"]:
                print("\nGoodbye! 🐺")
                return
            else:
                print("[!] Invalid choice. Please try again.")

    def do_help(self, args):
        """Display the help menu."""
        print("""
=============================================
💡 WireWolf Help Menu 💡
=============================================

Available Commands:
---------------------------------------------
1️⃣  `scan`: Perform a network scan.
    - Use `scan -t <target>` to scan a target.
    - Add options like `--dns`, `--subdomains`, `--vulnerabilities`, etc.
    - Example: `scan -t example.com --dns --vulnerabilities`

2️⃣  `update`: Update WireWolf to the latest version.
    - Type `update` to check for and install updates.

3️⃣  `menu`: Display a guided menu with all available options.

4️⃣  `exit`: Quit the WireWolf shell.
    - Simply type `exit` to leave the program.

For Detailed Guidance:
---------------------------------------------
- Use `scan -h` to view all scan options.
- Visit the documentation for examples and more details.

WireWolf Documentation: https://github.com/your-repo/WireWolf
        """)

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
            description="""
=============================================
🛠️  WireWolf Scan Command Help 🛠️
=============================================

Usage: `scan -t <target> [options]`

Options:
---------------------------------------------
-t, --target       Target IP or domain (Required).
-p, --ports        Ports to scan (Default: 80,443).
-o, --output       Save the results to a file.
-f, --fast         Fast mode: Scan IP, GeoIP, and common ports.
-v, --verbose      Show detailed progress during scan.
--subdomains       Enumerate subdomains for the domain.
--traceroute       Perform a traceroute to the target.
--dns              Fetch DNS records (A, MX).
--vulnerabilities  Scan for vulnerabilities.
--ssl-check        Check SSL/TLS configuration.
--passwords        Test password strength.
--sensitive-files  Search for sensitive files.

Examples:
---------------------------------------------
1️⃣  Scan example.com for open ports:
    🐺 `scan -t example.com`

2️⃣  Find subdomains and vulnerabilities:
    🐺 `scan -t example.com --subdomains --vulnerabilities`

3️⃣  Save results to a file:
    🐺 `scan -t example.com -o results.txt`
=============================================
            """,
            formatter_class=argparse.RawTextHelpFormatter,
            add_help=False,
        )

        parser.add_argument('-t', '--target', required=True, help='Target IP or domain to scan (required).')
        parser.add_argument('-p', '--ports', default='80,443', help='Specify ports to scan. (Default: 80,443)')
        parser.add_argument('-o', '--output', help='Save the scan results to a specified file.')
        parser.add_argument('-f', '--fast', action='store_true', help='Enable fast mode: Scan basic details only.')
        parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output.')
        parser.add_argument('--subdomains', action='store_true', help='Enumerate subdomains for the target domain.')
        parser.add_argument('--traceroute', action='store_true', help='Perform a traceroute to the target.')
        parser.add_argument('--dns', action='store_true', help='Retrieve DNS records for the target domain.')
        parser.add_argument('--vulnerabilities', action='store_true', help='Scan for vulnerabilities.')
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
            print("[!] Invalid command. Use `scan -h` for help.")

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
        geo_data = get_geoip(ip)
        port_data = scan_ports(ip, '80,443', verbose)
        generate_report(target, ip, geo_data, port_data, [], [], {}, [], output_file)
    else:
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
