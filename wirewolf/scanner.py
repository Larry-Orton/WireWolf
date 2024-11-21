
import nmap
import socket
import requests
from geoip2.database import Reader
from ipwhois import IPWhois

def scan_ports(ip):
    nm = nmap.PortScanner()
    print(f"\n[+] Scanning ports for {ip}...")
    nm.scan(ip, '1-65535', '-T4')
    for host in nm.all_hosts():
        print(f"Host: {host} ({nm[host].hostname()})")
        for proto in nm[host].all_protocols():
            print(f"Protocol: {proto}")
            ports = nm[host][proto].keys()
            for port in sorted(ports):
                state = nm[host][proto][port]['state']
                print(f"Port {port}: {state}")

def get_geoip(ip):
    try:
        reader = Reader('/path/to/GeoLite2-City.mmdb')  # Update with actual path
        response = reader.city(ip)
        print(f"\n[+] GeoIP Information for {ip}:")
        print(f"Country: {response.country.name}")
        print(f"City: {response.city.name}")
        print(f"Latitude: {response.location.latitude}")
        print(f"Longitude: {response.location.longitude}")
        reader.close()
    except Exception as e:
        print(f"[-] GeoIP lookup failed: {e}")

def get_website_info(url):
    try:
        response = requests.get(f"http://{url}")
        print(f"\n[+] Website Information for {url}:")
        print(f"Headers: {response.headers}")
        print(f"Status Code: {response.status_code}")
    except Exception as e:
        print(f"[-] Website lookup failed: {e}")

def whois_lookup(ip):
    try:
        obj = IPWhois(ip)
        results = obj.lookup_rdap()
        print(f"\n[+] Whois Information for {ip}:")
        print(f"ASN: {results.get('asn')}")
        print(f"ASN Description: {results.get('asn_description')}")
        print(f"Network: {results.get('network', {}).get('name')}")
    except Exception as e:
        print(f"[-] Whois lookup failed: {e}")

def main():
    print("==========================")
    print(" WireWolf Network Scanner")
    print("==========================")
    target = input("Enter the target IP or domain: ")
    ip = socket.gethostbyname(target)
    print(f"\nResolved IP: {ip}")
    
    scan_ports(ip)
    get_geoip(ip)
    whois_lookup(ip)
    if '.' in target:
        get_website_info(target)

if __name__ == "__main__":
    main()
