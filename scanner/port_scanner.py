import socket
def check_single_port(domain, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)  # Set a timeout for the connection attempt
        result = sock.connect_ex((domain, port))
        sock.close()
        return result == 0  # Port is open if result is 0
    except Exception as e:
        print(f"Error checking port {port} on {domain}: {e}")
        return False
def scan_common_ports(domain):
    common_ports = {
        21: "FTP",
        22: "SSH", 
        23: "Telnet", 
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3", 
        143: "IMAP",
        443: "HTTPS",
        3306: "MySQL",
        5432: "PostgreSQL",
        1433: "SQL Server"
      }

    print(f"Scanning {domain} for common ports...")
    results = {
    "domain": domain,
    "open_ports": [],
    "closed_ports": [],
    "risky_ports": []
    }
    for port, service in common_ports.items():
       print(f"Checking port {port} ({service})...")
       if check_single_port(domain, port):
           print(f"Port {port} ({service}) is open.")
           results["open_ports"].append({"port": port, "service": service})
           if port in [21, 3306, 3389]:  # Example of risky ports
               results["risky_ports"].append({"port": port, "service": service, "reason": 'This port should not be exposed to the internet'})
    else:
           print(f"Port {port} ({service}) is closed.")
           results["closed_ports"].append(port)
    return results
if __name__ == '__main__':
    result = scan_common_ports("google.com")
    print("\n=== RESULTS ===")
    print(f"Domain: {result['domain']}")
    print(f"\n Total Open Ports: {len(result['open_ports'])}")
    if result['open_ports']:
        print("\nOpen Ports:")
        for port_info in result['open_ports']:
            print(f" - Port {port_info['port']}: ({port_info['service']})")
            
    if result['risky_ports']:
        print(f"\nRisky Ports Detected: {len(result['risky_ports'])}")
        for risky in result['risky_ports']:
            print(f" Port {risky['port']}: {risky['service']} - {risky['reason']}")
    else:
        print("\nNo risky ports detected.")
    print(f"\n Closed Ports: {len(result['closed_ports'])}")