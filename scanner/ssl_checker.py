import ssl
import socket
from datetime import datetime

def check_ssl(domain):
    """
    Check if a domain has a valid SSL certificate.
    
    Returns: Dictionary with SSL information
    """
    results = {
        'domain': domain,
        'has_ssl': False,
        'valid': False,
        'issuer': None,
        'expires': None,
        'days_remaining': None,
        'errors': []
    }
    
    try:
        # Create SSL context
        context = ssl.create_default_context()
        
        # Connect to the domain on port 443 (HTTPS)
        print(f"Checking SSL for {domain}...")
        
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                # Get the certificate
                cert = ssock.getpeercert()
                
                results['has_ssl'] = True
                results['valid'] = True
                
                # Get who issued the certificate
                issuer = dict(x[0] for x in cert['issuer'])
                results['issuer'] = issuer.get('organizationName', 'Unknown')
                
                # Get expiration date
                expiry_date_str = cert['notAfter']
                # Format: 'Jan 15 23:59:59 2025 GMT'
                expiry_date = datetime.strptime(expiry_date_str, '%b %d %H:%M:%S %Y %Z')
                results['expires'] = expiry_date.strftime('%Y-%m-%d')
                
                # Calculate days until expiry
                days_left = (expiry_date - datetime.now()).days
                results['days_remaining'] = days_left
                
                # Check if expired
                if days_left < 0:
                    results['valid'] = False
                    results['errors'].append(f"Certificate expired {abs(days_left)} days ago!")
                elif days_left < 30:
                    results['errors'].append(f"Certificate expires soon ({days_left} days)")
                
        print(f"  ✓ SSL check complete")
        
    except ssl.SSLError as e:
        results['has_ssl'] = True  # Has SSL but with errors
        results['errors'].append(f"SSL Error: {str(e)}")
        print(f"  ✗ SSL Error: {str(e)}")
        
    except socket.gaierror:
        results['errors'].append("Could not resolve domain")
        print(f"  ✗ Could not resolve domain")
        
    except Exception as e:
        results['errors'].append(f"Connection error: {str(e)}")
        print(f"  ✗ Error: {str(e)}")
    
    return results


# Test the checker
if __name__ == '__main__':
    print("=== SSL Certificate Checker ===\n")
    
    # Test with a known good site
    result = check_ssl('fitgirl-repacks.site')
    
    print("\n=== RESULTS ===")
    print(f"Domain: {result['domain']}")
    print(f"Has SSL: {result['has_ssl']}")
    print(f"Valid: {result['valid']}")
    
    if result['issuer']:
        print(f"Issued by: {result['issuer']}")
    
    if result['expires']:
        print(f"Expires: {result['expires']}")
        print(f"Days remaining: {result['days_remaining']}")
    
    if result['errors']:
        print(f"\n⚠️  Issues Found:")
        for error in result['errors']:
            print(f"  - {error}")
    else:
        print("\n✓ No issues found!")