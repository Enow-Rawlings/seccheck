def calculate_security_score(results):
    """
    Calculate overall security score (0-100).
    
    Higher score = better security
    Lower score = more issues
    
    Returns: Dictionary with score and rating
    """
    score = 100  # Start perfect
    issues_found = []
    
    # ====================================================================
    # PORT SECURITY (max -30 points)
    # ====================================================================
    port_data = results.get('ports', {})
    
    # Deduct for risky ports
    risky_ports = port_data.get('risky_ports', [])
    for risky in risky_ports:
        score -= 15
        issues_found.append({
            'category': 'Ports',
            'severity': 'High',
            'issue': f"Port {risky['port']} exposed",
            'points_lost': 15
        })
    
    # Deduct if too many ports open (potential attack surface)
    open_ports = port_data.get('open_ports', [])
    if len(open_ports) > 5:
        score -= 5
        issues_found.append({
            'category': 'Ports',
            'severity': 'Low',
            'issue': f"{len(open_ports)} ports open (large attack surface)",
            'points_lost': 5
        })
    
    # ====================================================================
    # SSL/TLS SECURITY (max -35 points)
    # ====================================================================
    ssl_data = results.get('ssl', {})
    
    # No SSL at all - major issue
    if not ssl_data.get('has_ssl'):
        score -= 35
        issues_found.append({
            'category': 'SSL',
            'severity': 'Critical',
            'issue': 'No HTTPS encryption',
            'points_lost': 35
        })
    else:
        # Has SSL but invalid
        if not ssl_data.get('valid'):
            score -= 25
            issues_found.append({
                'category': 'SSL',
                'severity': 'High',
                'issue': 'Invalid SSL certificate',
                'points_lost': 25
            })
        
        # Certificate expiring soon
        days_remaining = ssl_data.get('days_remaining')
        if days_remaining and days_remaining < 30:
            score -= 10
            issues_found.append({
                'category': 'SSL',
                'severity': 'Medium',
                'issue': f'Certificate expires in {days_remaining} days',
                'points_lost': 10
            })
    
    # ====================================================================
    # HTTP HEADERS (max -25 points)
    # ====================================================================
    header_data = results.get('headers', {})
    
    missing_headers = header_data.get('missing_headers', [])
    for header in missing_headers:
        if header['risk'] == 'High':
            score -= 8
            issues_found.append({
                'category': 'Headers',
                'severity': 'High',
                'issue': f"Missing {header['name']}",
                'points_lost': 8
            })
        elif header['risk'] == 'Medium':
            score -= 4
            issues_found.append({
                'category': 'Headers',
                'severity': 'Medium',
                'issue': f"Missing {header['name']}",
                'points_lost': 4
            })
        elif header['risk'] == 'Low':
            score -= 2
            issues_found.append({
                'category': 'Headers',
                'severity': 'Low',
                'issue': f"Missing {header['name']}",
                'points_lost': 2
            })
    
    # ====================================================================
    # DNS CONFIGURATION (max -10 points)
    # ====================================================================
    dns_data = results.get('dns', {})
    
    dns_issues = dns_data.get('issues', [])
    for issue in dns_issues:
        if issue['severity'] == 'High':
            score -= 5
            issues_found.append({
                'category': 'DNS',
                'severity': 'High',
                'issue': issue['message'],
                'points_lost': 5
            })
        elif issue['severity'] == 'Medium':
            score -= 3
            issues_found.append({
                'category': 'DNS',
                'severity': 'Medium',
                'issue': issue['message'],
                'points_lost': 3
            })
        elif issue['severity'] == 'Low':
            score -= 1
            issues_found.append({
                'category': 'DNS',
                'severity': 'Low',
                'issue': issue['message'],
                'points_lost': 1
            })
    
    # ====================================================================
    # ENSURE SCORE STAYS IN RANGE
    # ====================================================================
    score = max(0, min(100, score))
    
    # ====================================================================
    # DETERMINE RATING
    # ====================================================================
    if score >= 90:
        rating = 'A'
        status = 'Excellent'
        color = 'success'
    elif score >= 80:
        rating = 'B'
        status = 'Good'
        color = 'success'
    elif score >= 70:
        rating = 'C'
        status = 'Fair'
        color = 'warning'
    elif score >= 60:
        rating = 'D'
        status = 'Poor'
        color = 'warning'
    else:
        rating = 'F'
        status = 'Critical'
        color = 'danger'
    
    return {
        'score': score,
        'rating': rating,
        'status': status,
        'color': color,
        'total_issues': len(issues_found),
        'issues_breakdown': issues_found,
        'breakdown': {
            'ports': sum(i['points_lost'] for i in issues_found if i['category'] == 'Ports'),
            'ssl': sum(i['points_lost'] for i in issues_found if i['category'] == 'SSL'),
            'headers': sum(i['points_lost'] for i in issues_found if i['category'] == 'Headers'),
            'dns': sum(i['points_lost'] for i in issues_found if i['category'] == 'DNS')
        }
    }


# Test the calculator
if __name__ == '__main__':
    # Sample test data
    test_results = {
        'ports': {
            'open_ports': [{'port': 80}, {'port': 443}],
            'risky_ports': []
        },
        'ssl': {
            'has_ssl': True,
            'valid': True,
            'days_remaining': 90
        },
        'headers': {
            'missing_headers': [
                {'name': 'Content-Security-Policy', 'risk': 'High'},
                {'name': 'Referrer-Policy', 'risk': 'Low'}
            ]
        },
        'dns': {
            'issues': [
                {'severity': 'Low', 'message': 'Only one mail server'}
            ]
        }
    }
    
    score_data = calculate_security_score(test_results)
    
    print("=== SECURITY SCORE TEST ===")
    print(f"Score: {score_data['score']}/100")
    print(f"Rating: {score_data['rating']} ({score_data['status']})")
    print(f"Total Issues: {score_data['total_issues']}")
    print(f"\nPoints Lost By Category:")
    print(f"  Ports: -{score_data['breakdown']['ports']}")
    print(f"  SSL: -{score_data['breakdown']['ssl']}")
    print(f"  Headers: -{score_data['breakdown']['headers']}")
    print(f"  DNS: -{score_data['breakdown']['dns']}")