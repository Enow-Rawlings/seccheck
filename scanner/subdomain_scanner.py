import requests
import dns.resolver
import re

def find_subdomains(domain):
    """
    Find subdomains for a given domain using multiple methods.
    
    Returns: List of discovered subdomains with basic info
    """
    results = {
        'domain': domain,
        'subdomains_found': [],
        'total_found': 0,
        'methods_used': [],
        'errors': []
    }
    
    print(f"🔍 Discovering subdomains for {domain}...")
    
    # Method 1: Certificate Transparency Logs (crt.sh)
    subdomains = find_via_crtsh(domain)
    if subdomains:
        results['methods_used'].append('Certificate Transparency')
        results['subdomains_found'].extend(subdomains)
    
    # Method 2: Common subdomain brute force
    common_subs = find_common_subdomains(domain)
    if common_subs:
        results['methods_used'].append('Common Names')
        # Only add if not already found
        for sub in common_subs:
            if sub not in results['subdomains_found']:
                results['subdomains_found'].append(sub)
    
    # Remove duplicates and sort
    results['subdomains_found'] = sorted(list(set(results['subdomains_found'])))
    results['total_found'] = len(results['subdomains_found'])
    
    print(f"✓ Found {results['total_found']} subdomains")
    
    return results


def find_via_crtsh(domain):
    """
    Find subdomains using Certificate Transparency logs via crt.sh
    This is free and very effective!
    """
    subdomains = []
    
    try:
        print(f"  → Checking Certificate Transparency logs...")
        
        # crt.sh API endpoint
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            # Extract unique subdomains from certificates
            for entry in data:
                name = entry.get('name_value', '')
                
                # Certificate names can have multiple subdomains
                names = name.split('\n')
                
                for n in names:
                    # Clean up the subdomain
                    n = n.strip().lower()
                    
                    # Remove wildcards
                    n = n.replace('*.', '')
                    
                    # Only add if it's actually a subdomain of our domain
                    if n.endswith(domain) and n != domain:
                        subdomains.append(n)
            
            print(f"    ✓ Found {len(set(subdomains))} subdomains via CT logs")
        
    except Exception as e:
        print(f"    ✗ CT log search failed: {str(e)}")
    
    return list(set(subdomains))


def find_common_subdomains(domain):
    """
    Try common subdomain names via DNS lookup.
    Quick brute force of most common subdomain patterns.
    """
    # Most common subdomain names
    common_names = [
        'www', 'mail', 'ftp', 'smtp', 'pop', 'ns1', 'ns2',
        'webmail', 'admin', 'dev', 'staging', 'test', 'demo',
        'api', 'blog', 'shop', 'store', 'portal', 'vpn',
        'remote', 'cloud', 'app', 'mobile', 'secure', 'ssl',
        'support', 'help', 'docs', 'cdn', 'static', 'assets'
    ]
    
    found = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2
    
    print(f"  → Checking common subdomain names...")
    
    for name in common_names:
        subdomain = f"{name}.{domain}"
        
        try:
            # Try to resolve the subdomain
            answers = resolver.resolve(subdomain, 'A')
            
            if answers:
                found.append(subdomain)
                
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            # Subdomain doesn't exist or no answer
            pass
        except Exception:
            # Other DNS errors
            pass
    
    if found:
        print(f"    ✓ Found {len(found)} via common names")
    
    return found


def scan_subdomain_security(subdomain):
    """
    Quick security check on a discovered subdomain.
    Just basic checks - ports and SSL.
    """
    from scanner.port_scanner import scan_common_ports
    from scanner.ssl_checker import check_ssl
    
    print(f"  → Scanning {subdomain}...")
    
    results = {
        'subdomain': subdomain,
        'ports': scan_common_ports(subdomain),
        'ssl': check_ssl(subdomain),
        'risk_score': 100  # Start at 100, deduct for issues
    }
    
    # Quick risk calculation
    risky_ports = results['ports'].get('risky_ports', [])
    if risky_ports:
        results['risk_score'] -= len(risky_ports) * 30
    
    if not results['ssl'].get('has_ssl'):
        results['risk_score'] -= 40
    elif not results['ssl'].get('valid'):
        results['risk_score'] -= 20
    
    results['risk_score'] = max(0, results['risk_score'])
    
    return results


# Test the scanner
if __name__ == '__main__':
    print("=== Subdomain Discovery Test ===\n")
    
    # Test with a known domain
    domain = "google.com"
    
    result = find_subdomains(domain)
    
    print(f"\n=== RESULTS ===")
    print(f"Domain: {result['domain']}")
    print(f"Total Subdomains Found: {result['total_found']}")
    print(f"Methods Used: {', '.join(result['methods_used'])}")
    
    if result['subdomains_found']:
        print(f"\nDiscovered Subdomains:")
        for i, sub in enumerate(result['subdomains_found'][:10], 1):
            print(f"  {i}. {sub}")
        
        if result['total_found'] > 10:
            print(f"  ... and {result['total_found'] - 10} more")
    
    # Test scanning one subdomain
    if result['subdomains_found']:
        print(f"\n=== Testing Security Scan on First Subdomain ===")
        first_sub = result['subdomains_found'][0]
        scan_result = scan_subdomain_security(first_sub)
        print(f"Subdomain: {scan_result['subdomain']}")
        print(f"Risk Score: {scan_result['risk_score']}/100")
        print(f"Risky Ports: {len(scan_result['ports'].get('risky_ports', []))}")
        print(f"SSL Valid: {scan_result['ssl'].get('valid', False)}")
