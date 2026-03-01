from dotenv import load_dotenv
load_dotenv()
from flask import Flask, render_template, request
from flask_mail import Mail, Message
from scanner.port_scanner import scan_common_ports
from scanner.ssl_checker import check_ssl
from scanner.header_checker import check_headers
from scanner.dns_checker import check_dns
from scanner.security_score import calculate_security_score
import os

app = Flask(__name__)

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
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
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
    
    return render_template('results.html', results=results)

@app.route('/download-pdf', methods=['POST'])
def download_pdf():
    """Generate and download PDF report"""
    from report.pdf_generator import generate_pdf_report
    from flask import send_file
    import json
    
    # Get the scan results from the form
    results_json = request.form.get('results')
    results = json.loads(results_json)
    
    # Generate PDF
    print(f"\n{'='*50}")
    print(f"Generating PDF report for: {results['domain']}")
    print(f"{'='*50}\n")
    
    pdf_path = generate_pdf_report(results)
    
    print("received pdf path:", pdf_path)
    # Send file to user
    return send_file(
        pdf_path,
        as_attachment=True,
        download_name=f"SecCheck_Report_{results['domain']}.pdf",
        mimetype='application/pdf'
    )

@app.route('/email-report', methods=['POST'])
def email_report():
    """Generate PDF and email it to user - async version"""
    from report.pdf_generator import generate_pdf_report
    import json
    import threading
    
    # Get data
    results_json = request.form.get('results')
    email = request.form.get('email')
    
    if not email or '@' not in email:
        return render_template('error.html',
            error_title="Invalid Email",
            error_message="Please provide a valid email address.",
            domain=None
        )
    
    results = json.loads(results_json)
    domain = results['domain']
    score = results['score']['score']
    
    # Send email in background thread (doesn't block)
    def send_email_async():
        with app.app_context():
            try:
                # Generate PDF
                pdf_path = generate_pdf_report(results)
                
                # Create email
                msg = Message(
                    subject=f"SecCheck Security Report - {domain}",
                    recipients=[email]
                )
                
                msg.body = f"""
Hello,

Your SecCheck security report for {domain} is ready!

Security Score: {score}/100

Please find the detailed PDF report attached.

Thank you for using SecCheck!
"""
                
                # Attach PDF
                with open(pdf_path, 'rb') as pdf_file:
                    msg.attach(
                        f"SecCheck_Report_{domain}.pdf",
                        "application/pdf",
                        pdf_file.read()
                    )
                
                # Send
                mail.send(msg)
                print(f"✓ Email sent to {email}")
                
            except Exception as e:
                print(f"✗ Email failed: {str(e)}")
    
    # Start background thread
    thread = threading.Thread(target=send_email_async)
    thread.start()
    
    # Return immediately (don't wait for email)
    return render_template('email_success.html', 
        email=email,
        domain=domain,
        score=score
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
    port = int(os.environ.get('PORT', 5000))
    #run in production mode
    app.run(host='0.0.0.0', debug=False, port=port)