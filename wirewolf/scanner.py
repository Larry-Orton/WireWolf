import nmap
import socket
import requests
from geoip2.database import Reader
from ipwhois import IPWhois

def scan_ports(ip):
    print(f"\nScanning ports for {ip}...")
    nm = nmap.PortScanner()
    nm.scan(ip, '1-65535', '-T4')
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

def main():
    print("==========================")
    print(" WireWolf Network Scanner")
    print("==========================")
    target = input("Enter the target IP or domain: ")
    ip = socket.gethostbyname(target)
    print(f"\nResolved IP: {ip}")
    scan_ports(ip)
    get_geoip(ip)

if __name__ == "__main__":
    main()
