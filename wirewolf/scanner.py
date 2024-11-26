import argparse
import nmap
import socket
import requests
from ipwhois import IPWhois
from datetime import datetime


def scan_ports(ip, ports, verbose):
    """Scan specified ports using Nmap."""
    results = []
    try:
        nm = nmap.PortScanner()
        if verbose:
            print(f"[Verbose] Scanning ports: {ports} for {ip}...")
        nm.scan(ip, ports, '-T4')  # -T4 ensures faster scanning
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

    if website_data:
        report.append("[+] Website Metadata:")
        report.append(f"    - Status Code: {website_data.get('status_code', 'unknown')}")
        report.append(f"    - Server: {website_data.get('server', 'unknown')}")
        report.append(f"    - Content-Type: {website_data.get('content_type', 'unknown')}\n")

    if whois_data:
        report.append("[+] Whois Information:")
        report.append(f"    - ASN: {whois_data.get('asn', 'unknown')}")
        report.append(f"    - Network: {whois_data.get('network', 'unknown')}")
        report.append(f"    - Org: {whois_data.get('org', 'unknown')}\n")

    report.append("--------------------------------")
    report.append("Scan Complete.")
    report.append("")

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
    """Main function to parse arguments and execute the tool."""
    parser = argparse.ArgumentParser(description="WireWolf Network Scanner")
    parser.add_argument('-t', '--target', required=True, help='Target IP or domain')
    parser.add_argument('-o', '--output', help='Save the scan results to a specified file')
    parser.add_argument('-p', '--ports', default='80,443', help='Ports to scan (default: 80,443)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output for detailed scanning progress')
    args = parser.parse_args()

    target = args.target
    ports = args.ports
    output_file = args.output
    verbose = args.verbose

    try:
        ip = socket.gethostbyname(target)
        if verbose:
            print(f"[Verbose] Resolved IP: {ip}")

        geo_data = get_geoip(ip)
        port_data = scan_ports(ip, ports, verbose)
        whois_data = whois_lookup(ip)
        website_data = website_metadata(target)

        generate_report(target, ip, geo_data, port_data, whois_data, website_data, output_file)

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user. Exiting gracefully.")
    except Exception as e:
        print(f"[!] An error occurred: {e}")


if __name__ == "__main__":
    main()
