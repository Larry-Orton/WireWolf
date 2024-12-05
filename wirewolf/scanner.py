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
import shutil
import os
import scapy.all as scapy

VERSION = "1.1.9"
AUTHOR = "Larry Orton"

# Global flag to stop the spinner
stop_spinner = False
# New Global Settings for Sniffing
sniff_duration = 60  # Sniff for 60 seconds by default

class WireWolfShell(Cmd):
    """Interactive shell for WireWolf."""
    prompt = "🐺 WireWolf> "
    intro = (
        "============================================="
        "\n __        __  _                                   "
        "\n \\ \\      / / | |                                "
        "\n  \\ \\ /\\ / /__| | ___ ___  _ __ ___   ___       "
        "\n   \\ V  V / _ \\ |/ __/ _ \\| '_  _ \\ / _ \\     "
        "\n    \\_/\\_/  __/ | (_| (_) | | | | | |  __/ |     "
        "\n         \\___|_|\\___\\___/|_| |_| |_|\\___|      "
        "\n                                                   "
        "\n        WireWolf - Network Scanner Tool            "
        "\n          Version: 1.2.0                           "
        "\n          Author: Larry Orton                      "
        "\n============================================="
        "\n\nType help for available commands."
        "\n"
    )
    def do_scan(self, args):
        """Scan a target. Usage: scan -t <target> [-p <ports>] [-o <output>] [-f] [-v]"""
        parser = argparse.ArgumentParser(prog="scan", add_help=False)
        parser.add_argument('-t', '--target', required=True, help='Target IP or domain to scan')
        parser.add_argument('-p', '--ports', default='80,443', help='Ports to scan (default: 80,443)')
        parser.add_argument('-o', '--output', help='Save the scan results to a specified file')
        parser.add_argument('-f', '--fast', action='store_true', help='Enable fast mode: scan basic details only')
        parser.add_argument('-d', '--deep', action='store_true', help='Enable deep mode: scan a broader range of ports')
        parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
        parser.add_argument('--subdomains', action='store_true', help='Enumerate subdomains for the target domain')
        parser.add_argument('--traceroute', action='store_true', help='Perform a traceroute to the target')
        parser.add_argument('--dns', action='store_true', help='Retrieve DNS records for the target domain')
        parser.add_argument('--ldapdump', action='store_true', help='Run ldapdomaindump for AD enumeration')
        parser.add_argument('-u', '--username', help='Username for AD enumeration (used with --ldapdump)')
        parser.add_argument('-P', '--password', help='Password for AD enumeration (used with --ldapdump)')
        
        try:
            args = parser.parse_args(args.split())
            target = args.target
            ports = '1-500' if args.deep else args.ports
            output_file = args.output
            fast = args.fast
            verbose = args.verbose
            subdomains = args.subdomains
            traceroute = args.traceroute
            dns_lookup = args.dns
            ldapdump = args.ldapdump
            username = args.username
            password = args.password

            # Run the scan with a loading animation
            run_with_spinner(
                perform_scan,
                target,
                ports,
                output_file,
                verbose,
                fast,
                subdomains,
                traceroute,
                dns_lookup,
                ldapdump,
                username,
                password
            )

        except SystemExit:
            print("[!] Invalid usage. Type help for usage details.")

    def do_exit(self, args):
        """Exit the WireWolf shell."""
        print("Goodbye!")
        return True
    def do_sniff(self, args):
        """Detective Mode: Sniff network packets for analysis. Usage: sniff [-t <duration>]"""
        parser = argparse.ArgumentParser(prog="sniff", add_help=False)
        parser.add_argument('-t', '--time', type=int, default=sniff_duration, help='Duration in seconds to sniff packets (default: 60 seconds)')
        
        try:
            args = parser.parse_args(args.split())
            sniff_time = args.time

            print("\n🔍 Entering Detective Mode...")
            run_with_spinner(sniff_packets, sniff_time)
        except SystemExit:
            print("[!] Invalid usage. Type help for usage details.")

def sniff_packets(duration):
    """Sniff packets on the network and provide a summary."""
    print(f"[+] Sniffing packets for {duration} seconds...")

    def process_packet(packet):
        print(f"🕵️ Captured Packet: {packet.summary()}")

    try:
        scapy.sniff(prn=process_packet, timeout=duration)
        print("[+] Detective Mode completed.")
        print("[Next Step] Review captured packet information to look for anomalies, interesting IPs, or suspicious activity.")
    except PermissionError:
        print("[!] Permission denied. Please run as root or with elevated privileges to sniff network packets.")
        
def do_help(self, args):
    """Display help information for available commands."""
    print("""
=============================================
                  HELP MENU                  
=============================================
Usage: scan [OPTIONS]

Options:
  -t, --target      <IP/Domain>    Specify the target domain or IP to scan (required).
  -o, --output      <File>         Save the scan results to the specified file.
  -p, --ports       <Ports>        Ports to scan (e.g., "80,443" or "1-1000"). Default: 80,443.
  -f, --fast                       Enable fast mode: scan only IP, GeoIP, and two common ports.
  -d, --deep                       Enable deep mode: scan a broader range of ports (1-65535).
  -v, --verbose                    Enable detailed output during scanning.
      --subdomains                 Enumerate subdomains for the target domain.
      --traceroute                 Perform a traceroute to the target IP.
      --dns                        Retrieve DNS records (A, MX) for the target domain.
      --ldapdump                   Run ldapdomaindump for Active Directory enumeration.
  -u, --username    <Username>     Username for AD enumeration (used with --ldapdump).
  -P, --password    <Password>     Password for AD enumeration (used with --ldapdump).
  -h, --help                       Display this help menu.

Commands:
  update                           Update the WireWolf tool from the command line.
  sniff                            Enter Detective Mode to sniff network packets for analysis.

Examples:
  1. Basic Scan:
     scan -t example.com
     
  2. Custom Ports:
     scan -t example.com -p 22,8080
  
  3. Save Report:
     scan -t example.com -o report.txt
  
  4. Fast Scan:
     scan -t example.com -f
  
  5. Deep Scan:
     scan -t example.com -d

  6. Subdomain Enumeration:
     scan -t example.com --subdomains

  7. Traceroute:
     scan -t 8.8.8.8 --traceroute

  8. DNS Lookup:
     scan -t example.com --dns

  9. LDAP Domain Dump Enumeration:
     scan -t example.com --ldapdump -u user -P pass

 10. Packet Sniffing (Detective Mode):
     sniff -t 60    # Sniff network packets for 60 seconds

=============================================
        """)


    def do_update(self, args):
        """Update the WireWolf tool from the command line."""
        try:
            print("Updating WireWolf...\n")
            result = subprocess.run(["pipx", "reinstall", "wirewolf"], capture_output=True, text=True)
            if result.returncode == 0:
                print("[+] WireWolf updated successfully!")
                print("[+] Restarting WireWolf...")
                sys.exit(0)  # Exit after update to restart
            else:
                print(f"[!] Update failed: {result.stderr}")
        except Exception as e:
            print(f"[!] Update process encountered an error: {e}")

def check_dependencies():
    """Check and install missing dependencies."""
    dependencies = ["docker", "nmap", "ldapdomaindump", "scapy"]
    
    for dep in dependencies:
        if shutil.which(dep) is None and dep != "scapy":
            print(f"[!] Missing dependency: {dep}. Attempting to install...")
            try:
                if dep == "docker":
                    subprocess.run(["sudo", "apt-get", "install", "-y", "docker.io"], check=True)
                    print("[+] Docker installed successfully.")
                elif dep == "nmap":
                    subprocess.run(["sudo", "apt-get", "install", "-y", "nmap"], check=True)
                    print("[+] Nmap installed successfully.")
                elif dep == "ldapdomaindump":
                    subprocess.run(["pip", "install", "ldapdomaindump"], check=True)
                    print("[+] ldapdomaindump installed successfully.")
            except subprocess.CalledProcessError:
                print(f"[!] Failed to install {dep}. Please install it manually.")
        elif dep == "scapy":
            try:
                # Attempt to import scapy
                import scapy
                print("[+] Scapy is already installed.")
            except ImportError:
                # If ImportError, try installing it
                print("[!] Scapy not found. Installing now...")
                try:
                    subprocess.run(["pip", "install", "scapy"], check=True)
                    import scapy  # Import again to confirm successful installation
                    print("[+] Scapy installed successfully.")
                except subprocess.CalledProcessError:
                    print("[!] Failed to install Scapy. Please install it manually.")
                
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

def perform_scan(target, ports, output_file, verbose, fast, subdomains, traceroute, dns_lookup, ldapdump, username, password):
    """Perform the full or fast scan based on user input."""
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[!] Error: Unable to resolve target '{target}'. Please check the target name.")
        return

    if fast:
        # Fast mode: Only IP resolution, GeoIP, and two common ports
        geo_data = get_geoip(ip)
        port_data = scan_ports(ip, '80,443', verbose)
        generate_fast_report(target, ip, geo_data, port_data, output_file)
    else:
        # Full or Deep scan
        geo_data = get_geoip(ip)
        port_data = scan_ports(ip, ports, verbose)
        whois_data = whois_lookup(ip)
        subdomains_data = enumerate_subdomains(target) if subdomains else []
        traceroute_data = trace_route(ip) if traceroute else []
        dns_data = lookup_dns(target) if dns_lookup else {}
        ldapdump_data = run_ldapdomaindump(target, username, password) if ldapdump else None
        generate_report(target, ip, geo_data, port_data, whois_data, subdomains_data, traceroute_data, dns_data, ldapdump_data, output_file)
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

def scan_ports(ip, ports, verbose):
    """Scan specified ports using Nmap."""
    results = []
    try:
        nm = nmap.PortScanner()
        if verbose:
            print(f"[Verbose] Scanning ports: {ports} for {ip}...")
        nm.scan(ip, ports, '-T4')
        for port in nm[ip]['tcp']:
            state = nm[ip]['tcp'][port]['state']
            service = nm[ip]['tcp'][port].get('name', 'unknown')
            results.append((port, state, service))
    except KeyError:
        print(f"[!] Error: Unable to scan ports for {ip}. Ensure the IP is reachable.")
    except Exception as e:
        print(f"[!] An error occurred during port scanning: {e}")
    return results

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
        result = subprocess.run(["tracert" if sys.platform == "win32" else "traceroute", ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            traceroute_output = result.stdout.splitlines()
        else:
            print(f"[!] Traceroute failed: {result.stderr}")
    except Exception as e:
        print(f"[!] Traceroute process encountered an error: {e}")
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

def run_ldapdomaindump(target, username, password):
    """Run ldapdomaindump to collect Active Directory information."""
    try:
        print(f"[+] Running ldapdomaindump for target: {target}")
        
        # Ensure output directory exists
        output_dir = f"{target}_ldapdomaindump"
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # Construct the ldapdomaindump command
        command = [
            "ldapdomaindump",
            "-u", username,
            "-p", password,
            "-o", output_dir,
            target
        ]
        
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"[+] ldapdomaindump completed successfully for target: {target}")
            return f"Results saved in directory: {output_dir}"
        else:
            print(f"[!] ldapdomaindump failed: {result.stderr}")
            return None
    except Exception as e:
        print(f"[!] ldapdomaindump encountered an error: {e}")
        return None
def generate_report(target, ip, geo_data, ports, whois_data, subdomains, traceroute, dns_data, ldapdump_data, output_file):
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
    report.append("    [Info] The IP address for the target has been resolved, which is essential for subsequent steps in network reconnaissance.\n")

    if geo_data:
        report.append("[+] GeoIP Information:")
        report.append(f"    - Country: {geo_data.get('country', 'unknown')}")
        report.append(f"    - Region: {geo_data.get('region', 'unknown')}")
        report.append(f"    - City: {geo_data.get('city', 'unknown')}")
        report.append(f"    - Latitude: {geo_data.get('latitude', 'unknown')}")
        report.append(f"    - Longitude: {geo_data.get('longitude', 'unknown')}\n")
        report.append("    [Info] Knowing the geographic location can be useful for determining the origin of potential threats or understanding network latency.\n")

    if ports:
        report.append("[+] Open Ports:")
        for port, state, service in ports:
            report.append(f"    - {port}/tcp: {state} ({service})")
            if state == 'open':
                report.append(f"        [Info] Port {port} is open. The service running is '{service}'.")
                report.append(f"        [Next Step] As a pentester, you might want to research vulnerabilities associated with '{service}' or use tools like Metasploit to identify potential exploits for open ports.\n")
        report.append("")

    if subdomains:
        report.append("[+] Subdomains Found:")
        for subdomain in subdomains:
            report.append(f"    - {subdomain}")
        report.append("    [Info] Enumerating subdomains can help in finding hidden services, administrative panels, or other entry points to the target.")
        report.append("    [Next Step] Consider scanning each subdomain for vulnerabilities, and exploring potential attack surfaces that they expose.\n")

    if traceroute:
        report.append("[+] Traceroute Results:")
        for hop in traceroute:
            report.append(f"    {hop}")
        report.append("    [Info] Traceroute helps you understand the path packets take to reach the target, which can reveal intermediate network devices and potential points of filtering or throttling.")
        report.append("    [Next Step] Use this information to identify bottlenecks or devices that could be used for deeper packet inspection.\n")

    if dns_data:
        report.append("[+] DNS Records:")
        for record_type, records in dns_data.items():
            report.append(f"    {record_type}:")
            for record in records:
                report.append(f"      - {record}")
        report.append("    [Info] DNS records provide information about how a domain resolves, including mail servers and IP addresses, which is useful in understanding the target's network structure.")
        report.append("    [Next Step] As a pentester, you may use this information to target specific IP addresses or MX records for email-based attacks.\n")

    if whois_data:
        report.append("[+] WHOIS Information:")
        report.append(f"    - ASN: {whois_data.get('asn', 'unknown')}")
        report.append(f"    - Organization: {whois_data.get('asn_description', 'unknown')}")
        report.append(f"    - CIDR: {whois_data.get('asn_cidr', 'unknown')}")
        report.append(f"    - Country: {whois_data.get('asn_country_code', 'unknown')}")
        report.append("    [Info] WHOIS information can provide ownership details, which are useful for understanding who is responsible for a specific IP or domain.")
        report.append("    [Next Step] You can use this information to perform targeted social engineering or identify points of contact for responsible disclosure.\n")

    if ldapdump_data:
        report.append("[+] LDAP Domain Dump Results:")
        report.append(ldapdump_data)
        report.append("    [Info] LDAP Domain Dump provides information about Active Directory structure and relationships.")
        report.append("    [Next Step] Use this information to identify privileged accounts, sensitive groups, or relationships that could be exploited.\n")

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
    check_dependencies()  # Ensure all dependencies are installed
    shell = WireWolfShell()
    shell.cmdloop()

if __name__ == "__main__":
    main()
