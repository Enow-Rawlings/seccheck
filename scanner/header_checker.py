import requests
from threading import Thread
import queue

def check_headers_with_timeout(domain, timeout=20):
    """Wrapper that enforces timeout using threading"""
    result_queue = queue.Queue()
    
    def worker():
        try:
            result = check_headers_internal(domain)
            result_queue.put(result)
        except Exception as e:
            result_queue.put({
                'domain': domain,
                'checked': False,
                'present_headers': [],
                'missing_headers': get_all_missing_headers(),
                'errors': [f"Error: {str(e)[:100]}"]
            })
    
    thread = Thread(target=worker)
    thread.daemon = True
    thread.start()
    thread.join(timeout=timeout)
    
    if thread.is_alive():
        # Timeout occurred
        print(f"  ⚠ Header check timed out after {timeout}s")
        return {
            'domain': domain,
            'checked': False,
            'present_headers': [],
            'missing_headers': get_all_missing_headers(),
            'errors': [f'Timeout after {timeout} seconds']
        }
    
    try:
        return result_queue.get_nowait()
    except queue.Empty:
        return {
            'domain': domain,
            'checked': False,
            'present_headers': [],
            'missing_headers': get_all_missing_headers(),
            'errors': ['Unknown error']
        }


def get_all_missing_headers():
    """Return all headers as missing"""
    important_headers = {
        'Strict-Transport-Security': {'description': 'Forces HTTPS connections', 'risk': 'High'},
        'Content-Security-Policy': {'description': 'Prevents XSS attacks', 'risk': 'High'},
        'X-Frame-Options': {'description': 'Prevents clickjacking', 'risk': 'Medium'},
        'X-Content-Type-Options': {'description': 'Prevents MIME sniffing', 'risk': 'Medium'},
        'Referrer-Policy': {'description': 'Controls referrer information', 'risk': 'Low'},
        'Permissions-Policy': {'description': 'Controls browser features', 'risk': 'Low'}
    }
    
    return [
        {
            'name': name,
            'description': info['description'],
            'risk': info['risk'],
            'note': 'Could not verify'
        }
        for name, info in important_headers.items()
    ]


def check_headers_internal(domain):
    """Internal header check function"""
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
    
    for protocol in ['https', 'http']:
        try:
            url = f"{protocol}://{domain}"
            
            response = requests.get(
                url,
                timeout=(5, 10),  # Very aggressive
                allow_redirects=False,  # Don't follow redirects
                headers={'User-Agent': 'SiteShield/1.0'}
            )
            
            results['checked'] = True
            
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
            
            print(f"  ✓ Headers checked via {protocol.upper()}")
            break  # Success
            
        except:
            if protocol == 'http':  # Last attempt
                for header_name, header_info in important_headers.items():
                    if header_name not in [h['name'] for h in results['missing_headers']]:
                        results['missing_headers'].append({
                            'name': header_name,
                            'description': header_info['description'],
                            'risk': header_info['risk']
                        })
            continue
    
    return results


# Main function to use
def check_headers(domain):
    """Check headers with enforced 20 second timeout"""
    return check_headers_with_timeout(domain, timeout=20)