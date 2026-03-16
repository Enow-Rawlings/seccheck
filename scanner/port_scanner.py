import socket

def check_single_port(domain, port):
    """Check if a single port is open on the domain"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)  # Increased from 2 to 3 seconds for reliability
        result = sock.connect_ex((domain, port))
        sock.close()
        return result == 0  # Port is open if result is 0
    except socket.timeout:
        # Port didn't respond in time - treat as closed
        return False
    except socket.gaierror:
        # DNS resolution failed
        print(f"  ⚠ Could not resolve domain for port {port}")
        return False
    except Exception as e:
        # Other errors - treat as closed
        print(f"  ⚠ Error checking port {port}: {str(e)[:50]}")
        return False


def scan_common_ports(domain):
    """Scan common ports on a domain"""
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
    
    # Risky ports that should not be exposed
    risky_port_list = [21, 22, 23, 3306, 5432, 3389, 1433, 25, 110, 143]

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
            
            # Check if this is a risky port
            if port in risky_port_list:
                results["risky_ports"].append({
                    "port": port, 
                    "service": service, 
                    "reason": f"{service} should not be exposed to the internet"
                })
        else:
            print(f"Port {port} ({service}) is closed.")
            results["closed_ports"].append(port)
    
    return results


if __name__ == '__main__':
    print("=== Port Scanner Test ===\n")
    
    result = scan_common_ports("google.com")
    
    print("\n=== RESULTS ===")
    print(f"Domain: {result['domain']}")
    print(f"\nTotal Open Ports: {len(result['open_ports'])}")
    
    if result['open_ports']:
        print("\n✓ Open Ports:")
        for port_info in result['open_ports']:
            print(f"  - Port {port_info['port']}: {port_info['service']}")
            
    if result['risky_ports']:
        print(f"\n⚠️  Risky Ports Detected: {len(result['risky_ports'])}")
        for risky in result['risky_ports']:
            print(f"  - Port {risky['port']}: {risky['service']}")
            print(f"    Reason: {risky['reason']}")
    else:
        print("\n✓ No risky ports detected.")
    
    print(f"\nClosed Ports: {len(result['closed_ports'])}")