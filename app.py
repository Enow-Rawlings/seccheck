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
if os.environ.get('RESEND_API_KEY'):
    # We'll use Flask-Mail but with Resend's SMTP
    app.config['MAIL_SERVER'] = 'smtp.resend.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = 'resend'
    app.config['MAIL_PASSWORD'] = os.environ.get('RESEND_API_KEY')
    app.config['MAIL_DEFAULT_SENDER'] = 'noreply@resend.dev'
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
    """Generate PDF report and send via email"""
    from report.pdf_generator import generate_pdf_report
    import json
    
    # Get the scan results and email from the form
    results_json = request.form.get('results')
    email = request.form.get('email')

    #validate email
    if not email or '@' not in email:
        return render_template('error.html', 
        error_Title='Invalid email address', 
        error_Message=f"The email address '{email}' does not appear to be valid. Please check and try again.", 
        domain=None
        )
    results = json.loads(results_json)
    domain = results['domain']
    # Generate PDF
    print(f"\n{'='*50}")
    print(f"Generating and emailing report for: {domain}")
    print(f"sending to: {email}")
    print(f"{'='*50}\n")

    try:
        #generate pdf 
        pdf_path = generate_pdf_report(results)

        #create email
        msg = Message(
            subject=f"SecCheck Report for {domain}",
            recipients=[email]
        )

        score  = results['score']['score']
        rating = results['score']['rating']
        msg.body = f"""
        Hello, 
        Your security report for {domain} is ready!
        Security Score: {score}/100 (Grade {rating})
        Please find the detailed PDF report attached to this email.
        Key Findings: 
        - Total issues found: {results['score']['total_issues']}
        - Port Security: {len(results['ports'].get('risky_ports', []))} risky ports found
        - SSL Status: {'Valid' if results['ssl'].get('valid') else 'Issues Detected'}
        - Missing Headers: {len(results['headers'].get('missing_headers', []))}

        Review the attached report for detailed findings and recommended fixes.

        Thank you for using SecCheck!
        
        ---
        SecCheck - Professional Website Security Scanner
        https://seccheck.io
        """
        #Attach PDF
        with open(pdf_path, 'rb') as pdf_file:
            msg.attach(f"SecCheck_Report_{domain}.pdf",
                        "application/pdf", 
                        pdf_file.read()
                        )
        #Send email
        mail.send(msg)
        print(f"Email sent successfully to {email}")

        #shpw success page
        return render_template('email_success.html',
                                email=email,
                                domain=domain,
                                score=score
                                )
    except Exception as e:
        print(f"Error sending email: {str(e)}")
        return render_template('error.html', 
        error_Title='Email Sending Failed', 
        error_Message=f"An error occurred while sending the email: {str(e)}. Please try again or try downloading the PDF instead. Error: {str(e)}", 
        domain=domain
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