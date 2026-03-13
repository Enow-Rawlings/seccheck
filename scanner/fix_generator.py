"""
AI-powered security fix generator using Groq (free & fast)
Falls back to templates if AI unavailable
"""

import os
from dotenv import load_dotenv
load_dotenv()

print(f"DEBUG: API KEY EXISTS: {bool(os.environ.get('GROQ_API_KEY'))}")

from groq import Groq
def generate_ai_fix(issue_type, issue_details, domain):
    """
    Generate custom fix using Groq AI (Llama 3.3 70B - FREE)
    Returns: Structured fix data or None if failed
    """
    
    api_key = os.environ.get('GROQ_API_KEY')
    
    if not api_key:
        print("  ⚠ No Groq API key, using template fix")
        return None
    
    try:
        client = Groq(api_key=api_key)
        
        # Build context-aware prompt
        prompt = f"""You are a cybersecurity expert helping a beginner fix a website security issue.

Domain: {domain}
Issue Type: {issue_type}
Issue Details: {issue_details}

Generate a beginner-friendly, step-by-step fix guide that:
1. Explains WHY this is dangerous (2-3 sentences, simple language)
2. Lists 3-4 specific impacts/risks
3. Provides SPECIFIC fix steps with actual commands
4. Includes options for: Linux/Ubuntu, cPanel, and Cloud providers (AWS/Azure/GCP)
5. Has verification steps
6. Uses encouraging, supportive tone

Format your response EXACTLY like this:

WHY IT MATTERS:
[2-3 sentences explaining the danger in simple terms]

POTENTIAL IMPACTS:
- [Impact 1]
- [Impact 2]
- [Impact 3]

FIX STEPS:

Step 1: [Title]
[Description]

For Linux/Ubuntu:
[commands or instructions]

For cPanel:
[instructions]

For Cloud Providers:
[instructions for AWS/Azure/GCP]

Step 2: [Verification title]
[How to test the fix worked]

Keep it under 400 words. Be specific, actionable, and kind."""

        # Call Groq API
        chat_completion = client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model="llama-3.3-70b-versatile",  # Fast & free model
            temperature=0.7,
            max_tokens=1024
        )
        
        fix_text = chat_completion.choices[0].message.content
        print(f"  ✓ AI-generated fix created (Groq)")
        
        return parse_ai_response(fix_text)
        
    except Exception as e:
        print(f"  ✗ Groq AI failed: {e}")
        return None


def parse_ai_response(ai_text):
    """
    Parse AI response into structured format
    Returns: dict with 'why', 'impacts', 'raw_text'
    """
    
    sections = {
        'why': '',
        'impacts': [],
        'raw_text': ai_text
    }
    
    # Extract "WHY IT MATTERS"
    if 'WHY IT MATTERS:' in ai_text:
        why_section = ai_text.split('WHY IT MATTERS:')[1].split('POTENTIAL IMPACTS:')[0]
        sections['why'] = why_section.strip()
    
    # Extract "POTENTIAL IMPACTS"
    if 'POTENTIAL IMPACTS:' in ai_text:
        impact_section = ai_text.split('POTENTIAL IMPACTS:')[1].split('FIX STEPS:')[0]
        impacts = [line.strip('- ').strip() for line in impact_section.split('\n') if line.strip().startswith('-')]
        sections['impacts'] = impacts
    
    return sections


def generate_port_fix(port_number, service_name, domain, use_ai=True):
    """
    Generate fix for exposed port - tries AI first, falls back to template
    """
    
    # Try AI generation
    if use_ai:
        issue_details = f"Port {port_number} ({service_name}) is exposed to the internet"
        
        ai_fix = generate_ai_fix('exposed_port', issue_details, domain)
        
        if ai_fix:
            return {
                'title': f'Close Port {port_number} ({service_name})',
                'severity': 'HIGH' if port_number in [21, 3306, 5432, 3389] else 'MEDIUM',
                'why': ai_fix.get('why', ''),
                'impacts': ai_fix.get('impacts', []),
                'ai_generated': True,
                'raw_fix': ai_fix.get('raw_text', ''),
                'time_estimate': '10-15 minutes',
                'difficulty': 'Medium'
            }
    
    # Fallback to templates
    return get_template_fix(port_number, service_name)


def get_template_fix(port_number, service_name):
    """
    Template-based fixes (fallback when AI unavailable)
    """
    
    templates = {
        21: {
            'title': f'Close FTP Port {port_number}',
            'severity': 'HIGH',
            'why': 'FTP transmits data unencrypted including passwords. Anyone can intercept your credentials.',
            'impacts': [
                'Attackers can steal login credentials',
                'Unauthorized file access/deletion',
                'Malware uploads possible'
            ],
            'raw_fix': """
WHY IT MATTERS:
FTP transmits all data unencrypted, including passwords. This makes it extremely easy for attackers to intercept your credentials.

POTENTIAL IMPACTS:
- Login credentials can be stolen
- Files can be modified or deleted
- Malware can be uploaded to your server

FIX STEPS:

Step 1: Disable FTP Service
For Linux: sudo systemctl stop vsftpd && sudo systemctl disable vsftpd
For cPanel: WHM → Service Configuration → FTP Server → Disable
For Cloud: Remove port 21 from Security Group rules

Step 2: Use SFTP Instead
SFTP uses SSH encryption. Connect using: sftp username@yourdomain.com
            """,
            'time_estimate': '5-10 minutes',
            'difficulty': 'Easy'
        },
        
        3306: {
            'title': f'URGENT: Close MySQL Port {port_number}',
            'severity': 'CRITICAL',
            'why': 'Your database is directly exposed to the internet. Attackers can attempt to steal ALL your data.',
            'impacts': [
                'Complete database theft possible',
                'Customer data exposed (GDPR violations)',
                'Ransomware attacks can encrypt your data',
                'Potential fines up to €20 million'
            ],
            'raw_fix': """
WHY IT MATTERS:
Your database is directly accessible from the internet. This is like leaving your house keys in the front door. Attackers can attempt to brute-force your password and steal EVERYTHING.

POTENTIAL IMPACTS:
- Complete database theft (ALL your data)
- Customer information exposed (GDPR violations)
- Website can be destroyed
- Ransomware attacks
- Fines up to €20 million or 4% revenue

FIX STEPS:

Step 1: Block Port 3306 Immediately
For Linux: sudo ufw deny 3306/tcp
For cPanel: WHM → ConfigServer Security & Firewall → Block 3306
For AWS: EC2 → Security Groups → Remove port 3306 from Inbound Rules
For Azure: Network Security Group → Delete port 3306 rule

Step 2: Verify Website Still Works
Your website connects via localhost, not internet. It should work fine after closing the port.
            """,
            'time_estimate': '5 minutes',
            'difficulty': 'Easy'
        }
    }
    
    # Return template or generic
    template = templates.get(port_number, {
        'title': f'Close Port {port_number} ({service_name})',
        'severity': 'MEDIUM',
        'why': f'Port {port_number} ({service_name}) is exposed and may provide attack vectors.',
        'impacts': [f'Unauthorized access via {service_name}'],
        'raw_fix': f'Block port {port_number} using firewall: sudo ufw deny {port_number}/tcp',
        'time_estimate': '5 minutes',
        'difficulty': 'Easy'
    })
    
    template['ai_generated'] = False
    return template


def generate_header_fix(header_name, domain, use_ai=True):
    """
    Generate fix for missing security header
    """
    
    # Try AI
    if use_ai:
        issue_details = f"Missing security header: {header_name}"
        
        ai_fix = generate_ai_fix('missing_header', issue_details, domain)
        
        if ai_fix:
            return {
                'title': f'Add {header_name} Header',
                'severity': 'HIGH' if header_name in ['Content-Security-Policy', 'Strict-Transport-Security'] else 'MEDIUM',
                'why': ai_fix.get('why', ''),
                'impacts': ai_fix.get('impacts', []),
                'ai_generated': True,
                'raw_fix': ai_fix.get('raw_text', ''),
                'time_estimate': '5 minutes',
                'difficulty': 'Easy'
            }
    
    # Fallback template
    return {
        'title': f'Add {header_name} Header',
        'severity': 'MEDIUM',
        'why': f'This header provides protection against common web attacks.',
        'impacts': ['Increased vulnerability to attacks'],
        'raw_fix': f'Add {header_name} to your web server configuration.',
        'ai_generated': False,
        'time_estimate': '5 minutes',
        'difficulty': 'Easy'
    }


# Test
if __name__ == '__main__':
    print("=== Testing AI Fix Generator ===\n")
    
    fix = generate_port_fix(3306, 'MySQL', 'example.com', use_ai=True)
    
    print(f"Title: {fix['title']}")
    print(f"AI Generated: {fix['ai_generated']}")
    print(f"\n{fix['raw_fix']}")
