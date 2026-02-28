import dns.resolver

def check_dns(domain):
    """
    Check DNS configuration for security issues.
    
    Returns: Dictionary with DNS analysis
    """
    results = {
        'domain': domain,
        'checked': False,
        'a_records': [],
        'mx_records': [],
        'ns_records': [],
        'txt_records': [],
        'has_spf': False,
        'issues': [],
        'info': []
    }
    
    try:
        print(f"Checking DNS for {domain}...")
        resolver = dns.resolver.Resolver()
        resolver.timeout = 10
        resolver.lifetime = 10
        resolver.nameservers = ['8.8.8.8', '8.8.4.4']
        results['checked'] = True
        
        # Check A Records (IPv4 addresses)
        try:
            a_records = resolver.resolve(domain, 'A')
            results['a_records'] = [str(r) for r in a_records]
            results['info'].append(f"Found {len(results['a_records'])} IP address(es)")
        except dns.resolver.NoAnswer:
            results['issues'].append({
                'type': 'A Record',
                'severity': 'High',
                'message': 'No A records found - domain may not be accessible'
            })
        except Exception as e:
            results['issues'].append({
                'type': 'A Record',
                'severity': 'Medium',
                'message': f'Could not resolve A records: {str(e)}'
            })
        
        # Check MX Records (Email servers)
        try:
            mx_records = resolver.resolve(domain, 'MX')
            results['mx_records'] = [
                {
                    'priority': mx.preference,
                    'server': str(mx.exchange).rstrip('.')
                }
                for mx in mx_records
            ]
            results['info'].append(f"Found {len(results['mx_records'])} mail server(s)")
            
            # Check for single point of failure
            if len(results['mx_records']) < 2:
                results['issues'].append({
                    'type': 'Email',
                    'severity': 'Low',
                    'message': 'Only one mail server configured - no redundancy'
                })
        except dns.resolver.NoAnswer:
            results['info'].append('No email servers configured (no MX records)')
        except Exception:
            pass
        
        # Check TXT Records (for SPF, verification, etc.)
        try:
            txt_records = resolver.resolve(domain, 'TXT')
            for txt in txt_records:
                txt_string = str(txt).strip('"')
                results['txt_records'].append(txt_string)
                
                # Check for SPF (email authentication)
                if txt_string.startswith('v=spf1'):
                    results['has_spf'] = True
                    results['info'].append('SPF record found - email authentication enabled')
                    
                    # Check for weak SPF
                    if '+all' in txt_string or '?all' in txt_string:
                        results['issues'].append({
                            'type': 'Email Security',
                            'severity': 'Medium',
                            'message': 'Weak SPF policy allows any server to send email'
                        })
        except dns.resolver.NoAnswer:
            pass
        except Exception:
            pass
        
        # If domain has email but no SPF
        if results['mx_records'] and not results['has_spf']:
            results['issues'].append({
                'type': 'Email Security',
                'severity': 'Medium',
                'message': 'No SPF record found - emails may be spoofed'
            })
        
        # Check NS Records (Nameservers)
        try:
            ns_records = resolver.resolve(domain, 'NS')
            results['ns_records'] = [str(r).rstrip('.') for r in ns_records]
            results['info'].append(f"Using {len(results['ns_records'])} nameserver(s)")
            
            # Check for redundancy
            if len(results['ns_records']) < 2:
                results['issues'].append({
'type': 'DNS',
                    'severity': 'High',
                    'message': 'Less than 2 nameservers - no redundancy if one fails'
                })
        except Exception:
            pass
        
        print(f"  ✓ DNS check complete")
        print(f"    IP addresses: {len(results['a_records'])}")
        print(f"    Mail servers: {len(results['mx_records'])}")
        print(f"    Issues found: {len(results['issues'])}")
        
    except Exception as e:
        results['issues'].append({
            'type': 'DNS',
            'severity': 'High',
            'message': f'DNS check failed: {str(e)}'
        })
        print(f"  ✗ DNS check error: {str(e)}")
    
    return results


# Test the checker
if __name__ == '__main__':
    print("=== DNS Configuration Checker ===\n")
    
    result = check_dns('google.com')
    
    print("\n=== RESULTS ===")
    print(f"Domain: {result['domain']}")
    
    if result['a_records']:
        print(f"\n📍 IP Addresses ({len(result['a_records'])}):")
        for ip in result['a_records']:
            print(f"  • {ip}")
    
    if result['mx_records']:
        print(f"\n📧 Mail Servers ({len(result['mx_records'])}):")
        for mx in result['mx_records']:
            print(f"  • {mx['server']} (priority: {mx['priority']})")
    
    if result['ns_records']:
        print(f"\n🌐 Nameservers ({len(result['ns_records'])}):")
        for ns in result['ns_records']:
            print(f"  • {ns}")
    
    print(f"\n✉️  SPF Record: {'✓ Found' if result['has_spf'] else '✗ Not found'}")
    
    if result['info']:
        print(f"\nℹ️  Information:")
        for info in result['info']:
            print(f"  • {info}")
    
    if result['issues']:
        print(f"\n⚠️  Issues Found ({len(result['issues'])}):")
        for issue in result['issues']:
            severity_icon = "🔴" if issue['severity'] == 'High' else "🟡" if issue['severity'] == 'Medium' else "🟢"
            print(f"  {severity_icon} [{issue['severity']}] {issue['type']}")
            print(f"    {issue['message']}")
    else:
        print("\n✓ No DNS issues found!")