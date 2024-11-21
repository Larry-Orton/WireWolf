import argparse
import nmap
import socket
import requests
from geoip2.database import Reader
from ipwhois import IPWhois

def scan_ports(ip, ports):
    print(f"\nScanning ports for {ip}...")
    nm = nmap.PortScanner()
    nm.scan(ip, ports, '-T4')
    for host in nm.all_hosts():
        print(f"Host: {host} ({nm[host].hostname()})")
        for proto in nm[host].all_protocols():
            print(f"Protocol: {proto}")
            ports = nm[host][proto].keys()
            for port in sorted(ports):
                print(f"Port {port}: {nm[host][proto][port]['state']}")

def get_geoip(ip):
    try:
        reader = Reader('/path/to/GeoLite2-City.mmdb')  # Update with your database path
        response = reader.city(ip)
        print(f"\nGeoIP Information for {ip}:")
        print(f"Country: {response.country.name}")
        print(f"City: {response.city.name}")
        print(f"Latitude: {response.location.latitude}")
        print(f"Longitude: {response.location.longitude}")
        reader.close()
    except Exception as e:
        print(f"GeoIP lookup failed: {e}")

def fast_scan(ip, ports):
    print("\n[Fast Mode] Scanning ports only...")
    scan_ports(ip, ports)
    print("[Fast Mode] Scan Complete.")

def main():
    parser = argparse.ArgumentParser(description="WireWolf Network Scanner")
    parser.add_argument('-t', '--target', required=True, help='Target IP or domain')
    parser.add_argument('-p', '--ports', default='1-65535', help='Ports to scan (e.g., 80,443 or 1-1000)')
    parser.add_argument('-f', '--fast', action='store_true', help='Run a faster scan with less detail')
    args = parser.parse_args()

    target = args.target
    ports = args.ports
    fast_mode = args.fast

    try:
        ip = socket.gethostbyname(target)
        print(f"Resolved IP: {ip}")

        if fast_mode:
            fast_scan(ip, ports)
        else:
            scan_ports(ip, ports)
            get_geoip(ip)
            # Add more functions for regular scan here (e.g., whois_lookup, website analysis)

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
