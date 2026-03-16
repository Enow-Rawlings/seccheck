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
        
        # Make HTTPS request to get headers with longer timeout
        url = f"https://{domain}"
        
        # Increased timeout to 20 seconds for slow domains
        response = requests.get(
            url, 
            timeout=20,  # Increased from 10 to 20 seconds
            allow_redirects=True,
            headers={'User-Agent': 'SiteShield-Security-Scanner/1.0'}  # Identify ourselves
        )
        
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
        
    except requests.exceptions.SSLError as e:
        error_msg = "SSL error - could not establish secure connection"
        results['errors'].append(error_msg)
        results['checked'] = True  # Mark as checked even with error
        print(f"  ⚠ SSL error (continuing scan)")
        
        # Try HTTP as fallback
        try:
            print(f"  → Retrying with HTTP...")
            url = f"http://{domain}"
            response = requests.get(url, timeout=20, allow_redirects=True)
            
            # Check headers from HTTP response
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
            
            print(f"  ✓ Headers check complete (via HTTP)")
            
        except Exception as fallback_error:
            print(f"  ✗ HTTP fallback also failed")
            results['errors'].append(f"Both HTTPS and HTTP failed: {str(fallback_error)}")
        
    except requests.exceptions.Timeout:
        error_msg = f"Request timed out after 20 seconds - {domain} is very slow"
        results['errors'].append(error_msg)
        results['checked'] = True  # Mark as checked
        
        # Still return missing headers since we couldn't check
        for header_name, header_info in important_headers.items():
            results['missing_headers'].append({
                'name': header_name,
                'description': header_info['description'],
                'risk': header_info['risk'],
                'note': 'Could not verify - timeout'
            })
        
        print(f"  ⚠ Timeout - domain too slow (marked all headers as missing)")
        
    except requests.exceptions.ConnectionError as e:
        error_msg = f"Could not connect to {domain}"
        results['errors'].append(error_msg)
        results['checked'] = True
        
        # Mark all as missing
        for header_name, header_info in important_headers.items():
            results['missing_headers'].append({
                'name': header_name,
                'description': header_info['description'],
                'risk': header_info['risk'],
                'note': 'Could not verify - connection failed'
            })
        
        print(f"  ⚠ Connection failed (marked all headers as missing)")
        
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        results['errors'].append(error_msg)
        results['checked'] = True
        
        # Mark all as missing
        for header_name, header_info in important_headers.items():
            results['missing_headers'].append({
                'name': header_name,
                'description': header_info['description'],
                'risk': header_info['risk'],
                'note': 'Could not verify - error occurred'
            })
        
        print(f"  ⚠ Error: {str(e)} (continuing scan)")
    
    return results


# Test the checker
if __name__ == '__main__':
    print("=== HTTP Security Headers Checker ===\n")
    
    result = check_headers('google.com')
    
    print("\n=== RESULTS ===")
    print(f"Domain: {result['domain']}")
    print(f"Total Headers Checked: {result['total_checked']}")
    print(f"Check Successful: {result['checked']}")
    
    if result['present_headers']:
        print(f"\n✓ Present Headers ({len(result['present_headers'])}):")
        for header in result['present_headers']:
            print(f"  • {header['name']}")
            print(f"    {header['description']}")
    
    if result['missing_headers']:
        print(f"\n⚠️  Missing Headers ({len(result['missing_headers'])}):")
        for header in result['missing_headers']:
            risk_icon = "🔴" if header['risk'] == 'High' else "🟡" if header['risk'] == 'Medium' else "🟢"
            note = f" ({header['note']})" if 'note' in header else ""
            print(f"  {risk_icon} {header['name']} [{header['risk']} Risk]{note}")
            print(f"    {header['description']}")
    
    if result['errors']:
        print(f"\n✗ Errors:")
        for error in result['errors']:
            print(f"  - {error}")



## Key Changes:

# 1. **Increased timeout:** 10s → 20s
# 2. **Better error handling:** SSL errors try HTTP fallback
# 3. **Timeout handling:** Marks headers as "could not verify" instead of crashing
# 4. **Connection errors:** Gracefully continues scan
# 5. **All errors:** Mark `checked = True` so scan continues
# 6. **Added User-Agent:** Identifies scanner to avoid blocking



## Also Update Procfile:


# web: gunicorn app:app --timeout 180 --workers 2