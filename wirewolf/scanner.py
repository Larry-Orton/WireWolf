import argparse
import nmap
import socket
import requests
from ipwhois import IPWhois
from datetime import datetime
from cmd import Cmd

VERSION = "1.0.0"
AUTHOR = "Your Name"


class WireWolfShell(Cmd):
    """Interactive shell for WireWolf."""
    prompt = "🐺 WireWolf> "
    intro = """
=============================================
      ██     ██ ██ ██████  ███████ ███    ██ 
      ██     ██ ██ ██   ██ ██      ████   ██ 
      ██  █  ██ ██ ██████  █████   ██ ██  ██ 
      ██ ███ ██ ██ ██   ██ ██      ██  ██ ██ 
       ███ ███  ██ ██   ██ ███████ ██   ████ 

        WireWolf - Network Scanner Tool
          Version: {1.0.0}
          Author: {Larry Orton}
=============================================

Type `help` for available commands.
    """.format(VERSION, AUTHOR)

    def do_scan(self, args):
        """Scan a target. Usage: scan -t <target> [-p <ports>] [-o <output>]"""
        parser = argparse.ArgumentParser(prog="scan", add_help=False)
        parser.add_argument('-t', '--target', required=True, help='Target IP or domain')
        parser.add_argument('-p', '--ports', default='80,443', help='Ports to scan (default: 80,443)')
        parser.add_argument('-o', '--output', help='Save the scan results to a specified file')
        try:
            args = parser.parse_args(args.split())
            target = args.target
            ports = args.ports
            output_file = args.output

            # Run the scan
            ip = socket.gethostbyname(target)
            geo_data = get_geoip(ip)
            port_data = scan_ports(ip, ports, verbose=False)
            whois_data = whois_lookup(ip)
            website_data = website_metadata(target)

            # Generate the report
            generate_report(target, ip, geo_data, port_data, whois_data, website_data, output_file)

        except SystemExit:
            print("[!] Invalid usage. Type `help scan` for usage details.")

    def do_exit(self, args):
        """Exit the WireWolf shell."""
        print("Goodbye!")
        return True

    def do_help(self, args):
        """Display help information for available commands."""
        print("""
Available commands:
  scan   - Run a scan. Usage: scan -t <target> [-p <ports>] [-o <output>]
  exit   - Exit the WireWolf shell.
  help   - Show this help message.
        """)


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
                'country': data['country'],
                'region': data['regionName'],
                'city': data['city'],
                'latitude': data['lat'],
                'longitude': data['lon']
            }
        else:
            print(f"[!] GeoIP lookup failed: {data['message']}")
    except Exception as e:
        print(f"[!] GeoIP lookup failed: {e}")
    return geo_data


def whois_lookup(ip):
    """Retrieve WHOIS information for the given IP."""
    whois_data = {}
    try:
        obj = IPWhois(ip)
        results = obj.lookup_rdap()
        whois_data = {
            'asn': results.get('asn'),
            'network': results.get('network', {}).get('name', 'unknown'),
            'org': results.get('asn_description', 'unknown'),
        }
    except Exception as e:
        print(f"[!] Whois lookup failed: {e}")
    return whois_data


def website_metadata(target):
    """Retrieve website metadata for the given target."""
    metadata = {}
    try:
        response = requests.get(f"http://{target}", timeout=5)
        metadata = {
            'status_code': response.status_code,
            'server': response.headers.get('Server', 'unknown'),
            'content_type': response.headers.get('Content-Type', 'unknown')
        }
    except Exception as e:
        print(f"[!] Website metadata lookup failed: {e}")
    return metadata


def generate_report(target, ip, geo_data, ports, whois_data, website_data, output_file):
    """Generate and print the final scan report."""
    # (Same implementation as above)
    pass


if __name__ == "__main__":
    shell = WireWolfShell()
    shell.cmdloop()
