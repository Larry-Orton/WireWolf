import argparse
import nmap
import socket
from geoip2.database import Reader

def scan_ports(ip, ports):
    """Scan specified ports using Nmap."""
    try:
        print(f"\nScanning ports for {ip}...")
        nm = nmap.PortScanner()
        nm.scan(ip, ports, '-T4')  # -T4 ensures faster scanning
        for port in map(int, ports.split(',')):  # Convert ports to integers
            state = nm[ip]['tcp'][port]['state'] if port in nm[ip]['tcp'] else "unknown"
            print(f"Port {port}: {state}")
    except KeyError:
        print(f"Error: Unable to scan ports for {ip}. Ensure the IP is reachable.")
    except Exception as e:
        print(f"An error occurred during port scanning: {e}")

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
        print(f"GeoIP lookup failed: {e}")

def fast_mode(ip):
    """Run a minimal scan in fast mode."""
    print("\n[Fast Mode] Running minimal scan...")
    print(f"IP Address: {ip}")
    get_geoip(ip)
    scan_ports(ip, "80,443")  # Scan only HTTP and HTTPS ports

def main():
    """Main function to parse arguments and execute the tool."""
    parser = argparse.ArgumentParser(description="WireWolf Network Scanner")
    parser.add_argument('-t', '--target', required=True, help='Target IP or domain')
    parser.add_argument('-f', '--fast', action='store_true', help='Run a faster scan with minimal details')
    args = parser.parse_args()

    target = args.target
    fast_mode_enabled = args.fast

    try:
        ip = socket.gethostbyname(target)
        print(f"\nResolved IP: {ip}")

        if fast_mode_enabled:
            fast_mode(ip)
        else:
            print("\n[Regular Mode] Not yet implemented in this example.")
            # Add additional functionality for regular mode if needed
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user. Exiting gracefully.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
