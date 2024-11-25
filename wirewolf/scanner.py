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
from bs4 import BeautifulSoup

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
-o, --output        Save the scan results to the specified file (supports HTML output).
-f, --fast          Enable fast mode: Scan basic details only (IP, GeoIP, ports 80,443).
-v, --verbose       Enable detailed output during the scan.
--subdomains        Enumerate subdomains for the target domain.
--traceroute        Perform a traceroute to the target IP.
--dns               Retrieve DNS records (A, MX) for the target domain.
--vulnerabilities   Scan for vulnerabilities based on detected services.
--fingerprint       Perform web application fingerprinting (CMS, technologies).
--ssl-check         Check SSL/TLS configurations (protocols, ciphers, cert expiry).
--passwords         Simulate password brute force using a wordlist.
--sensitive-files   Scan for exposed sensitive files (.env, .git, backups).
-h, --help          Display this help menu.

🚀 **EXAMPLES**
---------------------------------------------
1️⃣ Basic Scan:
   🐺 `scan -t example.com`

2️⃣ Scan Custom Ports:
   🐺 `scan -t example.com -p 22,8080`

3️⃣ Save Report to File (HTML):
   🐺 `scan -t example.com -o report.html`

4️⃣ Check SSL/TLS:
   🐺 `scan -t example.com --ssl-check`

5️⃣ Web Fingerprinting:
   🐺 `scan -t example.com --fingerprint`

6️⃣ Find Sensitive Files:
   🐺 `scan -t example.com --sensitive-files`

7️⃣ Simulate Password Attacks:
   🐺 `scan -t example.com --passwords`
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


def perform_scan(target, ports, output_file, verbose, fast, subdomains, traceroute, dns_lookup, vulnerabilities, fingerprint, ssl_check, passwords, sensitive_files):
    """Perform the full or fast scan based on user input."""
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


# Implementing the specific feature functions
def web_fingerprint(target):
    """Perform web application fingerprinting."""
    print("[+] Performing web application fingerprinting...")
    try:
        response = requests.get(f"http://{target}", timeout=5)
        headers = response.headers
        soup = BeautifulSoup(response.text, 'html.parser')
        return {
            "Title": soup.title.string if soup.title else "Unknown",
            "Server": headers.get('Server', 'Unknown'),
            "Powered-By": headers.get('X-Powered-By', 'Unknown')
        }
    except Exception as e:
        print(f"[!] Web application fingerprinting failed: {e}")
        return {}


def check_ssl_config(target):
    """Check SSL/TLS configurations."""
    print("[+] Checking SSL/TLS configurations...")
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

def scan_ports(ip, ports, verbose):
    """Scan specified ports using Nmap."""
    results = []
    try:
        nm = nmap.PortScanner()
        if verbose:
            print(f"[Verbose] Scanning ports: {ports} for {ip}...")
        nm.scan(ip, ports, '-T4')
        for port in sorted(map(int, ports.split(','))):
            state = nm[ip]['tcp'][port]['state'] if port in nm[ip]['tcp'] else "unknown"
            service = nm[ip]['tcp'][port].get('name', 'unknown') if port in nm[ip]['tcp'] else "unknown"
            results.append((port, state, service))
    except KeyError:
        print(f"[!] Error: Unable to scan ports for {ip}. Ensure the IP is reachable.")
    except Exception as e:
        print(f"[!] An error occurred during port scanning: {e}")
    return results


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
        else:
            print(f"[!] GeoIP lookup failed: {data.get('message', 'Unknown error')}")
    except Exception as e:
        print(f"[!] GeoIP lookup failed: {e}")
    return geo_data


def scan_vulnerabilities(service_data):
    """Scan for vulnerabilities based on identified services."""
    vulnerabilities = []
    try:
        for service in service_data:
            port, state, service_name = service
            if service_name != 'unknown':
                print(f"Scanning vulnerabilities for {service_name}...")
                response = requests.get(f"https://cve.circl.lu/api/search/{service_name}")
                if response.status_code == 200:
                    cve_data = response.json()
                    if 'results' in cve_data:
                        for item in cve_data['results']:
                            vulnerabilities.append({
                                'service': service_name,
                                'port': port,
                                'cve': item.get('id', 'Unknown CVE ID'),
                                'description': item.get('summary', 'No description available'),
                                'score': item.get('cvss', {}).get('score', 'N/A')
                            })
    except Exception as e:
        print(f"[!] Vulnerability scanning failed: {e}")
    return vulnerabilities


def whois_lookup(ip):
    """Perform WHOIS lookup for the target IP."""
    whois_data = {}
    try:
        obj = IPWhois(ip)
        result = obj.lookup_rdap()
        whois_data = {
            'asn': result.get('asn', 'Unknown'),
            'asn_description': result.get('asn_description', 'Unknown'),
            'asn_cidr': result.get('asn_cidr', 'Unknown'),
            'asn_country_code': result.get('asn_country_code', 'Unknown')
        }
    except Exception as e:
        print(f"[!] WHOIS lookup failed: {e}")
    return whois_data


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
    except Exception:
        pass
    return subdomains


def trace_route(ip):
    """Perform a traceroute to the target IP."""
    traceroute_output = []
    try:
        result = subprocess.run(["traceroute", ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        traceroute_output = result.stdout.decode().splitlines()
    except Exception:
        pass
    return traceroute_output


def lookup_dns(domain):
    """Retrieve DNS records for the domain."""
    dns_data = {}
    try:
        dns_data["A"] = [rdata.to_text() for rdata in dns.resolver.resolve(domain, "A")]
        dns_data["MX"] = [rdata.to_text() for rdata in dns.resolver.resolve(domain, "MX")]
    except Exception:
        pass
    return dns_data


def generate_report(target, ip, geo_data, ports, whois_data, subdomains, traceroute, dns_data, vulnerabilities, output_file):
    """Generate a comprehensive report based on the scan results."""
    report = []
    report.append("==========================")
    report.append(" WireWolf Network Scanner")
    report.append("==========================\n")
    report.append(f"Target: {target} ({ip})")
    report.append(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append("================================\n")

    report.append("[+] Resolved IP Address:")
    report.append(f"    - {ip}\n")

    if geo_data:
        report.append("[+] GeoIP Information:")
        report.append(f"    - Country: {geo_data.get('country', 'unknown')}")
        report.append(f"    - Region: {geo_data.get('region', 'unknown')}")
        report.append(f"    - City: {geo_data.get('city', 'unknown')}")
        report.append(f"    - Latitude: {geo_data.get('latitude', 'unknown')}")
        report.append(f"    - Longitude: {geo_data.get('longitude', 'unknown')}\n")

    if ports:
        report.append("[+] Open Ports:")
        for port, state, service in ports:
            report.append(f"    - {port}/tcp: {state} ({service})")
        report.append("")

    if subdomains:
        report.append("[+] Subdomains Found:")
        for subdomain in subdomains:
            report.append(f"    - {subdomain}")
        report.append("")

    if traceroute:
        report.append("[+] Traceroute Results:")
        for hop in traceroute:
            report.append(f"    {hop}")
        report.append("")

    if dns_data:
        report.append("[+] DNS Records:")
        for record_type, records in dns_data.items():
            report.append(f"    {record_type}:")
            for record in records:
                report.append(f"      - {record}")
        report.append("")

    if whois_data:
        report.append("[+] WHOIS Information:")
        report.append(f"    - ASN: {whois_data.get('asn', 'unknown')}")
        report.append(f"    - Organization: {whois_data.get('asn_description', 'unknown')}")
        report.append(f"    - CIDR: {whois_data.get('asn_cidr', 'unknown')}")
        report.append(f"    - Country: {whois_data.get('asn_country_code', 'unknown')}")
        report.append("")

    if vulnerabilities:
        report.append("[+] Identified Vulnerabilities:")
        for vuln in vulnerabilities:
            report.append(f"    - Service: {vuln['service']} (Port: {vuln['port']})")
            report.append(f"      CVE: {vuln['cve']} | Score: {vuln['score']}")
            report.append(f"      Description: {vuln['description']}\n")
    else:
        # Funny message if no vulnerabilities are found
        report.append("[+] Vulnerability Scan Results:")
        report.append("    - No Vuln, She's Clean! 🚿✨\n")

    report.append("--------------------------------")
    report.append("Scan Complete.")
    report.append("")

    # Print the report to the console
    report_str = "\n".join(report)
    print(report_str)

    # Save to file if output_file is specified
    if output_file:
        try:
            with open(output_file, 'w') as f:
                f.write(report_str)
            print(f"[+] Report saved to {output_file}")
        except Exception as e:
            print(f"[!] Failed to save report: {e}")


def main():
    """Entry point for the tool."""
    shell = WireWolfShell()
    shell.cmdloop()


if __name__ == "__main__":
    main()
