from dotenv import load_dotenv
load_dotenv()
from flask import Flask, render_template, request, send_file, Response, stream_with_context, session, redirect
import json
import time
from flask_mail import Mail, Message
from scanner.port_scanner import scan_common_ports
from scanner.ssl_checker import check_ssl
from scanner.header_checker import check_headers
from scanner.dns_checker import check_dns
from scanner.security_score import calculate_security_score
import os

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# Configure email settings
# Check for Resend first (easiest)
# Brevo (works on Railway, no card needed)
if os.environ.get('BREVO_SMTP_KEY'):
    app.config['MAIL_SERVER'] = 'smtp-relay.brevo.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = os.environ.get('BREVO_SMTP_USER')
    app.config['MAIL_PASSWORD'] = os.environ.get('BREVO_SMTP_KEY')
    app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('BREVO_SMTP_USER')
else:
    # Gmail fallback
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USER')
    app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASS')
    app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('EMAIL_USER')


mail = Mail(app)

@app.route('/')
@app.route('/')
def index():
    """Homepage"""
    prefill_domain = request.args.get('domain', '')
    return render_template('index.html', prefill_domain=prefill_domain)

@app.route('/scan', methods=['POST'])
def scan():
    """Redirect to scanning page with animation"""
    domain = request.form.get('domain', '').strip()
    domain = domain.replace('https://', '').replace('http://', '').replace('www.', '')
    
    # Basic validation
    if not domain or len(domain) < 4 or '.' not in domain:
        return render_template('error.html', 
            error_Title='Invalid Domain', 
            error_Message='Please enter a valid domain name.', 
            domain=domain
        )
    
    # Quick DNS check
    import socket
    try:
        socket.gethostbyname(domain)
    except socket.gaierror:
        return render_template('error.html', 
            error_Title='Domain Not Found', 
            error_Message=f"Could not find '{domain}'. Please check spelling.", 
            domain=domain
        )
    
    # Show scanning animation
    return render_template('scanning.html', domain=domain)


@app.route('/scan-stream/<domain>')
def scan_stream(domain):
    """Server-Sent Events for real-time scan progress"""
    from flask import Response, stream_with_context
    import time
    
    def generate():
        try:
            # Start
            yield f"data: {json.dumps({'step': 'start', 'message': 'Starting scan...', 'progress': 0})}\n\n"
            time.sleep(0.3)
            
            # Port scan
            yield f"data: {json.dumps({'step': 'ports', 'message': '🔌 Scanning ports...', 'progress': 15})}\n\n"
            port_results = scan_common_ports(domain)
            open_count = len(port_results.get('open_ports', []))
            risky_count = len(port_results.get('risky_ports', []))
            yield f"data: {json.dumps({'step': 'ports_done', 'message': f'Found {open_count} open ports ({risky_count} risky)', 'progress': 35})}\n\n"
            
            # SSL
            yield f"data: {json.dumps({'step': 'ssl', 'message': '🔒 Checking SSL certificate...', 'progress': 50})}\n\n"
            ssl_results = check_ssl(domain)
            ssl_msg = '✓ Valid SSL' if ssl_results.get('valid') else '⚠ SSL issues detected'
            yield f"data: {json.dumps({'step': 'ssl_done', 'message': ssl_msg, 'progress': 60})}\n\n"
            
            # Headers
            yield f"data: {json.dumps({'step': 'headers', 'message': '📋 Analyzing security headers...', 'progress': 70})}\n\n"
            header_results = check_headers(domain)
            missing_count = len(header_results.get('missing_headers', []))
            yield f"data: {json.dumps({'step': 'headers_done', 'message': f'{missing_count} headers missing', 'progress': 80})}\n\n"
            
            # DNS
            yield f"data: {json.dumps({'step': 'dns', 'message': '🌐 Checking DNS configuration...', 'progress': 90})}\n\n"
            dns_results = check_dns(domain)
            yield f"data: {json.dumps({'step': 'dns_done', 'message': 'DNS check complete', 'progress': 95})}\n\n"
            
            # Calculate score
            results = {
                'domain': domain,
                'ports': port_results,
                'ssl': ssl_results,
                'headers': header_results,
                'dns': dns_results
            }
            
            yield f"data: {json.dumps({'step': 'scoring', 'message': '📊 Calculating security score...', 'progress': 98})}\n\n"
            score_data = calculate_security_score(results)
            results['score'] = score_data
            
            # Save to database
            from database import save_scan, get_scan_history
            user_ip = request.remote_addr
            scan_id = save_scan(domain, results, user_ip)
            
            # Get history
            history = get_scan_history(domain, limit=5)
            
            # Store in session for results page
                        # Complete
            score_value = score_data.get('score', 0)
            grade = score_data.get('grade', 'F')
            
            # Redirect to results with scan_id
            yield f"data: {json.dumps({'step': 'complete', 'message': f'Complete! Score: {score_value}/100 (Grade {grade})', 'progress': 100, 'redirect': f'/results/{scan_id}'})}\n\n"

        except Exception as e:
            print(f"Scan error: {e}")
            import traceback
            traceback.print_exc()
            yield f"data: {json.dumps({'step': 'error', 'message': f'Scan failed: {str(e)}', 'progress': 0})}\n\n"
    
    return Response(stream_with_context(generate()), content_type='text/event-stream')


@app.route('/history')
def scan_history():
    """Show all scan history for all domains"""
    from database import get_all_scans_grouped
    
    # Get all scans grouped by domain
    history = get_all_scans_grouped(limit=50)
    
    return render_template('history.html', history=history)


@app.route('/results/<int:scan_id>')
def show_results(scan_id):
    """Display scan results from database"""
    from database import get_scan_by_id, get_scan_history
    
    # Get scan from database
    scan = get_scan_by_id(scan_id)
    
    if not scan:
        return redirect('/')
    
    # Parse results JSON
    results = json.loads(scan['results'])
    domain = scan['domain']
    
    # Get history
    history = get_scan_history(domain, limit=5)
    
    return render_template('results.html', results=results, history=history, scan_id=scan_id)



# @app.route('/scan-process', methods=['POST'])
# def scan_process():
    # Get the domain from the form
    domain = request.form.get('domain')
    
    # Clean up the domain
    domain = domain.replace('https://', '').replace('http://', '').replace('www.', '').strip()

    # Check if the domain is valid
    if not domain:
        return render_template('error.html', 
        error_Title='No domain provided', 
        error_Message='Please enter a valid domain to scan.', 
        domain=None
        )
    if len(domain) < 4 or '.' not in domain:
        return render_template('error.html', 
        error_Title='Invalid domain format', 
        error_Message=f"The domain '{domain}' does not appear to be valid. Please check and try again.", #'The domain you entered does not appear to be valid. Please check and try again.', 
        domain=domain
        )
    import socket
    try:
        socket.gethostbyname(domain)
    except socket.gaierror:
        return render_template('error.html', 
        error_Title='Domain not found', 
        error_Message=f"The domain '{domain}' could not be found. Please check the spelling and try again.", #'The domain you entered could not be found. Please check the spelling and try again.', 
        domain=domain
        )

        # Domain is valid, proceed with scanning

    
    # Run all scanners
    print(f"\n{'='*50}")
    print(f"Starting scan for: {domain}")
    print(f"{'='*50}\n")
    
    port_results = scan_common_ports(domain)
    ssl_results = check_ssl(domain)
    header_results = check_headers(domain)
    dns_results = check_dns(domain)
    
    # Combine results
    results = {
        'domain': domain,
        'ports': port_results,
        'ssl': ssl_results,
        'headers': header_results,
        'dns': dns_results
    }
    
    # Calculate security score
    score_data = calculate_security_score(results)
    results['score'] = score_data
    
    print(f"\n{'='*50}")
    print(f"Security Score: {score_data['score']}/100 ({score_data['rating']})")
    print(f"Complete Scan Finished!")
    print(f"{'='*50}\n")
    
    # Save scan to database
    from database import save_scan, get_scan_history
    user_ip = request.remote_addr
    save_scan(domain, results, user_ip)
    
    # Get scan history for this domain
    history = get_scan_history(domain, limit=5)
    
    return render_template('results.html', results=results, history=history)


@app.route('/download-pdf/<int:scan_id>', methods=['POST', 'GET'])
def download_pdf(scan_id):
    try:
        from report.pdf_generator import generate_pdf_report
        from database import get_scan_by_id
        
        # Get scan from database
        scan = get_scan_by_id(scan_id)
        if not scan:
            raise Exception("Scan not found")
        
        results = json.loads(scan['results'])
        
        # Generate PDF
        print(f"\n{'='*50}")
        print(f"Generating PDF report for: {results['domain']}")
        print(f"{'='*50}\n")
        
        pdf_path = generate_pdf_report(results)
        
        print("received pdf path:", pdf_path)
        
        # Verify file exists before sending
        if not os.path.exists(pdf_path):
            print(f"ERROR: PDF file not found at {pdf_path}")
            return render_template('error.html', 
                error_Title='PDF Generation Error', 
                error_Message='The PDF file could not be created. Please try again.', 
                domain=results['domain']
            )
        
        # Send file to user
        return send_file(
            pdf_path,
            as_attachment=True,
            download_name=f"SiteShield_Report_{results['domain']}.pdf",
            mimetype='application/pdf'
        )
        
    except Exception as e:
        print(f"ERROR in download_pdf: {e}")
        import traceback
        traceback.print_exc()
        return render_template('error.html', 
            error_Title='PDF Download Error', 
            error_Message=f'An error occurred while generating the PDF: {str(e)}', 
            domain=None
        )


@app.route('/email-report/<int:scan_id>', methods=['POST'])
def email_report(scan_id):
    try:
        from report.pdf_generator import generate_pdf_report
        from database import get_scan_by_id
        import base64
        import requests as req
        
        email = request.form.get('email')
        
        if not email or '@' not in email:
            return render_template('error.html',
                error_title="Invalid Email",
                error_message="Please enter a valid email.",
                domain=None
            )
        
        # Get scan from database
        scan = get_scan_by_id(scan_id)
        if not scan:
            raise Exception("Scan not found")
        
        results = json.loads(scan['results'])
        domain = results['domain']
        score = results['score']['score']
        
        def send_via_api():
            with app.app_context():
                try:
                    # Generate PDF
                    pdf_path = generate_pdf_report(results)
                    
                    # Read PDF as base64
                    with open(pdf_path, 'rb') as f:
                        pdf_base64 = base64.b64encode(f.read()).decode()
                    
                    # Brevo API
                    url = "https://api.brevo.com/v3/smtp/email"
                    headers = {
                        "accept": "application/json",
                        "content-type": "application/json",
                        "api-key": os.environ.get('BREVO_API_KEY')
                    }
                    
                    payload = {
                        "sender": {"email": os.environ.get('BREVO_SMTP_USER')},
                        "to": [{"email": email}],
                        "subject": f"SiteShield Security Report - {domain}",
                        "htmlContent": f"<p>Your security report for {domain} is attached. Score: {score}/100</p>",
                        "attachment": [{
                            "content": pdf_base64,
                            "name": f"SiteShield_Report_{domain}.pdf"
                        }]
                    }
                    
                    response = req.post(url, json=payload, headers=headers)
                    print(f"✓ Email sent via API: {response.status_code}")
                    
                except Exception as e:
                    print(f"✗ API failed: {e}")
        
        import threading
        threading.Thread(target=send_via_api).start()
        
        return render_template('email_success.html', email=email, domain=domain, score=score)
        
    except Exception as e:
        print(f"ERROR in email_report: {e}")
        import traceback
        traceback.print_exc()
        return render_template('error.html',
            error_title="Email Failed",
            error_message="Could not send email. Please try downloading instead.",
            domain=None
        )

    # Send email with PDF attachment
    print(f"Sending email to: {email}")
    
    msg = Message(
        subject=f"SecCheck Report for {results['domain']}",
        recipients=[recipient_email]
    )
    msg.body = f"Please find attached the security report for {results['domain']}."
    
    with app.open_resource(pdf_path) as pdf_file:
        msg.attach(f"SecCheck_Report_{results['domain']}.pdf", "application/pdf", pdf_file.read())
    
    mail.send(msg)
    
    return render_template('email_success.html', email=recipient_email)


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    #run in production mode
    app.run(host='0.0.0.0', debug=True, port=port)