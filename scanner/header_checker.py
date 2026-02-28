import requests

def check_headers(domain):
    """
    Check if a website has important security headers.
    
    Returns: Dictionary with header analysis
    """
    # These are the critical security headers
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
    
    try:
        print(f"Checking HTTP headers for {domain}...")
        
        # Make HTTPS request to get headers
        url = f"https://{domain}"
        response = requests.get(url, timeout=10, allow_redirects=True)
        
        results['checked'] = True
        
        # Check each important header
        for header_name, header_info in important_headers.items():
            if header_name in response.headers:
                # Header is present
                results['present_headers'].append({
                    'name': header_name,
                    'value': response.headers[header_name],
                    'description': header_info['description']
                })
            else:
                # Header is missing
                results['missing_headers'].append({
                    'name': header_name,
                    'description': header_info['description'],
                    'risk': header_info['risk']
                })
        
        print(f"  ✓ Headers check complete")
        print(f"    Present: {len(results['present_headers'])}")
        print(f"    Missing: {len(results['missing_headers'])}")
        
    except requests.exceptions.SSLError:
        results['errors'].append("SSL error - could not establish secure connection")
        print(f"  ✗ SSL error")
        
    except requests.exceptions.Timeout:
        results['errors'].append("Request timed out")
        print(f"  ✗ Timeout")
        
    except Exception as e:
        results['errors'].append(f"Error: {str(e)}")
        print(f"  ✗ Error: {str(e)}")
    
    return results


# Test the checker
if __name__ == '__main__':
    print("=== HTTP Security Headers Checker ===\n")
    
    result = check_headers('google.com')
    
    print("\n=== RESULTS ===")
    print(f"Domain: {result['domain']}")
    print(f"Total Headers Checked: {result['total_checked']}")
    
    if result['present_headers']:
        print(f"\n✓ Present Headers ({len(result['present_headers'])}):")
        for header in result['present_headers']:
            print(f"  • {header['name']}")
            print(f"    {header['description']}")
    
    if result['missing_headers']:
        print(f"\n⚠️  Missing Headers ({len(result['missing_headers'])}):")
        for header in result['missing_headers']:
            risk_icon = "🔴" if header['risk'] == 'High' else "🟡" if header['risk'] == 'Medium' else "🟢"
            print(f"  {risk_icon} {header['name']} [{header['risk']} Risk]")
            print(f"    {header['description']}")
    
    if result['errors']:
        print(f"\n✗ Errors:")
        for error in result['errors']:
            print(f"  - {error}")