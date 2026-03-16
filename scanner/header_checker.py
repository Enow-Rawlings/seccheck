import requests
from urllib3.util.timeout import Timeout
import socket

# Set global socket timeout as failsafe
socket.setdefaulttimeout(15)


def check_headers(domain):
    """
    Check if a website has important security headers.
    
    Returns: Dictionary with header analysis
    """
    important_headers = {
        'Strict-Transport-Security': {
            'description': 'Forces HTTPS connections',
            'risk': 'High'
        },
        'Content-Security-Policy': {
            'description': 'Prevents XSS attacks',
            'risk': 'High'
        },
        'X-Frame-Options': {
            'description': 'Prevents clickjacking',
            'risk': 'Medium'
        },
        'X-Content-Type-Options': {
            'description': 'Prevents MIME sniffing',
            'risk': 'Medium'
        },
        'Referrer-Policy': {
            'description': 'Controls referrer information',
            'risk': 'Low'
        },
        'Permissions-Policy': {
            'description': 'Controls browser features',
            'risk': 'Low'
        }
    }
    
    results = {
        'domain': domain,
        'checked': False,
        'present_headers': [],
        'missing_headers': [],
        'total_checked': len(important_headers),
        'errors': []
    }
    
    print(f"Checking HTTP headers for {domain}...")
    
    # Try HTTPS first with aggressive timeout
    for protocol in ['https', 'http']:
        try:
            url = f"{protocol}://{domain}"
            
            # Create session with custom timeout adapter
            session = requests.Session()
            
            # Very aggressive timeout: 8s to connect, 12s to read
            response = session.get(
                url,
                timeout=(8, 12),
                allow_redirects=True,
                headers={'User-Agent': 'SiteShield-Security-Scanner/1.0'}
            )
            
            results['checked'] = True
            
            # Check headers
            for header_name, header_info in important_headers.items():
                if header_name in response.headers:
                    results['present_headers'].append({
                        'name': header_name,
                        'value': response.headers[header_name],
                        'description': header_info['description']
                    })
                else:
                    results['missing_headers'].append({
                        'name': header_name,
                        'description': header_info['description'],
                        'risk': header_info['risk']
                    })
            
            print(f"  ✓ Headers check complete (via {protocol.upper()})")
            print(f"    Present: {len(results['present_headers'])}")
            print(f"    Missing: {len(results['missing_headers'])}")
            
            # Success - don't try other protocol
            break
            
        except requests.exceptions.Timeout:
            print(f"  ⚠ Timeout on {protocol.upper()} - trying next...")
            
            if protocol == 'http':  # Last attempt failed
                results['errors'].append(f"Timeout - {domain} too slow (>20 seconds)")
                results['checked'] = True
                
                # Mark all as missing
                for header_name, header_info in important_headers.items():
                    if header_name not in [h['name'] for h in results['missing_headers']]:
                        results['missing_headers'].append({
                            'name': header_name,
                            'description': header_info['description'],
                            'risk': header_info['risk'],
                            'note': 'Could not verify - timeout'
                        })
            
            continue  # Try next protocol
            
        except requests.exceptions.ConnectionError:
            print(f"  ⚠ Connection failed on {protocol.upper()} - trying next...")
            
            if protocol == 'http':  # Last attempt
                results['errors'].append(f"Connection failed - {domain} unreachable")
                results['checked'] = True
                
                # Mark all as missing
                for header_name, header_info in important_headers.items():
                    if header_name not in [h['name'] for h in results['missing_headers']]:
                        results['missing_headers'].append({
                            'name': header_name,
                            'description': header_info['description'],
                            'risk': header_info['risk'],
                            'note': 'Could not verify - unreachable'
                        })
            
            continue
            
        except Exception as e:
            print(f"  ⚠ Error on {protocol.upper()}: {str(e)[:50]}")
            
            if protocol == 'http':  # Last attempt
                results['errors'].append(f"Error: {str(e)[:100]}")
                results['checked'] = True
                
                # Mark all as missing
                for header_name, header_info in important_headers.items():
                    if header_name not in [h['name'] for h in results['missing_headers']]:
                        results['missing_headers'].append({
                            'name': header_name,
                            'description': header_info['description'],
                            'risk': header_info['risk'],
                            'note': 'Could not verify - error'
                        })
            
            continue
    
    return results