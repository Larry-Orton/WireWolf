import argparse
import nmap
import socket
import requests
from ipwhois import IPWhois

def scan_ports(ip, ports):
    """Scan specified ports using Nmap."""
    try:
        print(f"\nScanning ports for {ip}...")
        nm = nmap.PortScanner()
        nm.scan(ip, ports, '-T4')  # -T4 ensures faster scanning
        for port in sorted(map(int, ports.split(','))):  # Convert ports to integers
            state = nm[ip]['tcp'][port]['state'] if port in nm[ip]['tcp'] else "unknown"
            print(f"Port {port}: {state}")
    except KeyError:
        print(f"[!] Error: Unable to scan ports for {ip}. Ensure the IP is reachable.")
    except Exception as e:
        print(f"[!] An error occurred during port scanning: {e}")

def get_geoip(ip):
    """Retrieve geographic information for the given IP using ip-api.com."""
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()
        if data['status'] == 'success':
            print(f"\nGeoIP Information for {ip}:")
            print(f"  Country: {data['country']}")
            print(f"  Region: {data['regionName']}")
            print(f"  City: {data['city']}")
            print(f"  Latitude: {data['lat']}")
            print(f"  Longitude: {data['lon']}")
        else:
            print(f"[!] GeoIP lookup failed: {data['message']}")
    except Exception as e:
        print(f"[!] GeoIP lookup failed: {e}")

def whois_lookup(ip):
    """Retrieve WHOIS information for the given IP."""
    try:
        obj = IPWhois(ip)
        results = obj.lookup_rdap()
        print(f"\nWhois Information for {ip}:")
        print(f"  ASN: {results.get('asn')}")
        print(f"  Network: {results.get('network', {}).get('name')}")
        print(f"  Org: {results.get('asn_description')}")
    except Exception as e:
        print(f"[!] Whois lookup failed: {e}")

def website_metadata(target):
    """Retrieve website metadata for the given target."""
    try:
        response = requests.get(f"http://{target}", timeout=5)
        print(f"\nWebsite Metadata for {target}:")
        print(f"  Status Code: {response.status_code}")
        print(f"  Server: {response.headers.get('Server', 'Unknown')}")
        print(f"  Content-Type: {response.headers.get('Content-Type', 'Unknown')}")
    except Exception as e:
        print(f"[!] Website metadata lookup failed: {e}")

def regular_mode(ip, target, ports):
    """Run the regular scan mode."""
    print("\n[Regular Mode] Running comprehensive scan...")
    get_geoip(ip)
    whois_lookup(ip)
    website_metadata(target)
    scan_ports(ip, ports)

def fast_mode(ip):
    """Run the fast scan mode."""
    print("\n[Fast Mode] Running minimal scan...")
    print(f"IP Address: {ip}")
    get_geoip(ip)
    scan_ports(ip, "80,443")  # Scan only HTTP and HTTPS ports

def main():
    """Main function to parse arguments and execute the tool."""
    parser = argparse.ArgumentParser(description="WireWolf Network Scanner")
    parser.add_argument('-t', '--target', required=True, help='Target IP or domain')
    parser.add_argument('-p', '--ports', default='1-65535', help='Ports to scan (default: all ports)')
    parser.add_argument('-f', '--fast', action='store_true', help='Run a faster scan with minimal details')
    args = parser.parse_args()

    target = args.target
    ports = args.ports
    fast_mode_enabled = args.fast

    try:
        ip = socket.gethostbyname(target)
        print(f"\nResolved IP: {ip}")

        if fast_mode_enabled:
            fast_mode(ip)
        else:
            regular_mode(ip, target, ports)

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user. Exiting gracefully.")
    except Exception as e:
        print(f"[!] An error occurred: {e}")

if __name__ == "__main__":
    main()
