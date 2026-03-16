import socket

def check_single_port(ip, port):
    """Check if a single port is open"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False


def scan_common_ports(domain):
    """Scan common ports"""
    common_ports = {
        21: "FTP", 22: "SSH", 80: "HTTP", 443: "HTTPS",
        3306: "MySQL", 5432: "PostgreSQL"
    }
    
    risky_port_list = [21, 22, 3306, 5432]
    
    print(f"Scanning {domain} for common ports...")
    
    try:
        ip = socket.gethostbyname(domain)
        print(f"  → Resolved to IP: {ip}")
    except:
        return {
            "domain": domain, "open_ports": [],
            "closed_ports": [], "risky_ports": [],
            "error": "DNS failed"
        }
    
    results = {"domain": domain, "open_ports": [], "closed_ports": [], "risky_ports": []}
    
    for port, service in common_ports.items():
        if check_single_port(ip, port):
            results["open_ports"].append({"port": port, "service": service})
            if port in risky_port_list:
                results["risky_ports"].append({"port": port, "service": service, "reason": f"{service} exposed"})
        else:
            results["closed_ports"].append(port)
    
    return results