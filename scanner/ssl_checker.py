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
        
        # Set aggressive timeout - 10 seconds max
        with socket.create_connection((domain, 443), timeout=10) as sock:
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
        error_msg = str(e)
        
        # Make SSL errors more user-friendly
        if 'CERTIFICATE_VERIFY_FAILED' in error_msg:
            results['errors'].append("SSL certificate verification failed - certificate may be self-signed or invalid")
        elif 'SSLV3_ALERT_HANDSHAKE_FAILURE' in error_msg:
            results['errors'].append("SSL handshake failed - server may use outdated encryption")
        else:
            results['errors'].append(f"SSL Error: {error_msg[:100]}")  # Truncate long errors
        
        print(f"  ⚠ SSL Error: {error_msg[:50]}...")
        
    except socket.timeout:
        # Specific handling for timeout
        results['errors'].append(f"Connection timeout - {domain} took too long to respond (>10 seconds)")
        results['has_ssl'] = False  # Can't verify
        print(f"  ⚠ Timeout - domain too slow to respond")
        
    except socket.gaierror:
        results['errors'].append("Could not resolve domain - DNS lookup failed")
        print(f"  ✗ Could not resolve domain")
        
    except ConnectionRefusedError:
        results['errors'].append("Connection refused - server rejected connection on port 443")
        results['has_ssl'] = False
        print(f"  ✗ Connection refused")
        
    except OSError as e:
        # Catch network-related errors
        error_msg = str(e)
        if 'timed out' in error_msg.lower():
            results['errors'].append(f"Connection timeout - {domain} did not respond")
            print(f"  ⚠ Connection timed out")
        elif 'refused' in error_msg.lower():
            results['errors'].append("Connection refused - no HTTPS service available")
            print(f"  ✗ Connection refused")
        else:
            results['errors'].append(f"Network error: {error_msg[:100]}")
            print(f"  ✗ Network error: {error_msg[:50]}...")
        
    except Exception as e:
        # Catch-all for any other errors
        error_msg = str(e)
        
        # Check if it's a timeout-related error
        if 'timed out' in error_msg.lower() or 'timeout' in error_msg.lower():
            results['errors'].append(f"Timeout - {domain} too slow to respond")
            print(f"  ⚠ Timeout")
        else:
            results['errors'].append(f"Error: {error_msg[:100]}")
            print(f"  ✗ Error: {error_msg[:50]}...")
    
    return results


# Test the checker
if __name__ == '__main__':
    print("=== SSL Certificate Checker ===\n")
    
    # Test with multiple domains
    test_domains = [
        'google.com',      # Should pass
        'expired.badssl.com',  # Expired cert
        'self-signed.badssl.com',  # Self-signed
        'nonexistent-domain-12345.com'  # Doesn't exist
    ]
    
    for domain in test_domains:
        print(f"\n{'='*50}")
        result = check_ssl(domain)
        
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
        
        print(f"{'='*50}")