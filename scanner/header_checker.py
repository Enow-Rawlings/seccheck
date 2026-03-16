import requests

def check_headers(domain):
    """
    Check headers with minimal timeout - fail fast
    """
    important_headers = {
        'Strict-Transport-Security': {'description': 'Forces HTTPS connections', 'risk': 'High'},
        'Content-Security-Policy': {'description': 'Prevents XSS attacks', 'risk': 'High'},
        'X-Frame-Options': {'description': 'Prevents clickjacking', 'risk': 'Medium'},
        'X-Content-Type-Options': {'description': 'Prevents MIME sniffing', 'risk': 'Medium'},
        'Referrer-Policy': {'description': 'Controls referrer information', 'risk': 'Low'},
        'Permissions-Policy': {'description': 'Controls browser features', 'risk': 'Low'}
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
    
    # Try HTTPS, then HTTP - with VERY short timeout
    for protocol in ['https', 'http']:
        try:
            url = f"{protocol}://{domain}"
            
            # Super aggressive timeout: 3s connect, 5s read = 8s max total
            response = requests.get(
                url,
                timeout=(3, 5),
                allow_redirects=False,
                headers={'User-Agent': 'SiteShield/1.0'}
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
            
            print(f"  ✓ Headers checked ({protocol.upper()})")
            return results  # Success - exit immediately
            
        except requests.exceptions.Timeout:
            print(f"  ⚠ Timeout on {protocol.upper()}")
            continue
            
        except requests.exceptions.RequestException:
            print(f"  ⚠ Failed on {protocol.upper()}")
            continue
            
        except Exception as e:
            print(f"  ⚠ Error: {str(e)[:30]}")
            continue
    
    # Both protocols failed - mark all as missing
    print(f"  ✗ Could not check headers - domain too slow or unreachable")
    
    results['checked'] = True
    results['errors'].append("Could not connect - domain unreachable or too slow")
    
    for header_name, header_info in important_headers.items():
        results['missing_headers'].append({
            'name': header_name,
            'description': header_info['description'],
            'risk': header_info['risk'],
            'note': 'Could not verify'
        })
    
    return results

## AND: Increase Gunicorn Timeout to 10 Minutes

# **Update `Procfile`:**
# web: gunicorn app:app --timeout 600 --graceful-timeout 600 --workers 2