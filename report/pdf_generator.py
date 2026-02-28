from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from datetime import datetime
# from reportlab.lib.pa
from reportlab.pdfgen import canvas
import os

def generate_pdf_report(results, output_dir='reports'):
    """
    Generate a professional PDF security report.
    """
    # Create reports directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Create filename
    domain = results['domain']
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"SecCheck_Report_{domain}_{timestamp}.pdf"
    filepath = os.path.join(output_dir, filename)
    
    # Create PDF document
    doc = SimpleDocTemplate(
        filepath,
        pagesize=letter,
        rightMargin=72,
        leftMargin=72,
        topMargin=72,
        bottomMargin=50
    )
    
    # Container for PDF elements
    story = []
    
    # Get styles
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=40,
        textColor=colors.HexColor('#2563eb'),
        spaceAfter=20,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    )
    
    subtitle_style = ParagraphStyle(
        'Subtitle',
        parent=styles['Normal'],
        fontSize=20,
        alignment=TA_CENTER,
        spaceAfter=30,
        textColor=colors.HexColor('#64748b')
    )
    body_style = ParagraphStyle(
        'BodyStyle',
        parent=styles['Normal'],
        fontSize=12,
        leading=16
    )
    
    warning_heading = ParagraphStyle(
        'WarningHeading',
        parent=styles['Heading4'],
        fontSize=13,
        textColor=colors.HexColor('#dc2626'),
        spaceAfter=10
    )

    info_heading = ParagraphStyle(
        'InfoHeading',
        parent=styles['Heading4'],
        fontSize=13,
        textColor=colors.HexColor('#2563eb'),
        spaceAfter=10
    )

    success_heading = ParagraphStyle(
        'SuccessHeading',
        parent=styles['Heading4'],
        fontSize=13,
        textColor=colors.HexColor('#059669'),
        spaceAfter=10
    )

    # ========================================================================
    # COVER PAGE
    # ========================================================================
    
    story.append(Spacer(1, 1.5*inch))
    story.append(Paragraph("Website Security Report", title_style))
    story.append(Paragraph(f"<b>{domain}</b>", subtitle_style))
    
    # Security Score - BIG with better spacing
    score_data = results.get('score', {})
    score = score_data.get('score', 0)
    rating = score_data.get('rating', 'N/A')
    status = score_data.get('status', 'Unknown')
    
    # Score color based on grade
    if score >= 80:
        score_color = colors.HexColor('#10b981')
    elif score >= 60:
        score_color = colors.HexColor('#f59e0b')
    else:
        score_color = colors.HexColor('#ef4444')
    
    story.append(Spacer(1, 0.8*inch))
    
    # Score number - HUGE
    score_text = f'<font size="84" color="{score_color.hexval()}"><b>{score}</b></font>'
    score_style = ParagraphStyle('Score', parent=body_style, alignment=TA_CENTER, leading=90)
    story.append(Paragraph(score_text, score_style))
    
    story.append(Spacer(1, 0.7*inch))
    
    # Grade and status - separate line with spacing
    grade_text = f'<font size="28" color="{score_color.hexval()}"><b>Grade {rating}</b></font>'
    grade_style = ParagraphStyle('Grade', parent=body_style, alignment=TA_CENTER, leading=32)
    story.append(Paragraph(grade_text, grade_style))
    
    story.append(Spacer(1, 0.35*inch))
    
    status_text = f'<font size="20" color="{score_color.hexval()}">{status}</font>'
    story.append(Paragraph(status_text, score_style))
    
    # Issues summary
    story.append(Spacer(1, 0.5*inch))
    issues_text = f'<font size="14" color="#64748b"><i>{score_data.get("total_issues", 0)} security issues identified</i></font>'
    story.append(Paragraph(issues_text, score_style))
    
    # Date and branding
    story.append(Spacer(1, 1.2*inch))
    date_text = f"<font size='11'>Report generated on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}</font>"
    date_style = ParagraphStyle('Date', parent=body_style, alignment=TA_CENTER, textColor=colors.grey)
    story.append(Paragraph(date_text, date_style))
    
    story.append(Spacer(1, 0.3*inch))
    brand_text = '<font size="12"><b>SecCheck</b> - Professional Website Security Scanner</font><br/><font size="10">https://seccheck.io</font>'
    story.append(Paragraph(brand_text, date_style))
    
    story.append(PageBreak())
    
    # ========================================================================
    # EXECUTIVE SUMMARY (Enhanced with insights)
    # ========================================================================
    
    story.append(Paragraph("Executive Summary", styles['Heading1']))
    story.append(Spacer(1, 0.3*inch))
    
    # Risk assessment paragraph
    risk_assessment = get_risk_assessment(score, score_data)
    
    summary = f"""
    This comprehensive security assessment of <b>{domain}</b> was conducted on 
    {datetime.now().strftime('%B %d, %Y')}. Our automated security scanner performed 
    in-depth analysis across four critical security domains: network port configuration, 
    SSL/TLS encryption, HTTP security headers, and DNS infrastructure.
    <br/><br/>
    <b>Overall Security Rating: {score}/100 (Grade {rating} - {status})</b>
    <br/><br/>
    {risk_assessment}
    <br/><br/>
    <b>Key Metrics:</b><br/>
    • Total Security Issues: {score_data.get('total_issues', 0)}<br/>
    • Critical/High Risk Items: {count_high_risk_issues(results)}<br/>
    • Medium Risk Items: {count_medium_risk_issues(results)}<br/>
    • Low Risk Items: {count_low_risk_issues(results)}
    """
    
    normal_justified = ParagraphStyle(
        'NormalJustified',
        parent=styles['Normal'],
        alignment=TA_JUSTIFY,
        spaceAfter=12
    )
    
    story.append(Paragraph(summary, normal_justified))
    story.append(Spacer(1, 0.3*inch))
    
    # Summary table with better styling
    summary_data = [
        ['Security Domain', 'Status', 'Issues Found', 'Risk Level'],
        ['Port Security', get_status_icon(results['ports']), count_port_issues(results['ports']), get_risk_level_ports(results['ports'])],
        ['SSL/TLS Encryption', get_status_icon(results['ssl']), count_ssl_issues(results['ssl']), get_risk_level_ssl(results['ssl'])],
        ['HTTP Security Headers', get_status_icon(results['headers']), count_header_issues(results['headers']), get_risk_level_headers(results['headers'])],
        ['DNS Configuration', get_status_icon(results['dns']), count_dns_issues(results['dns']), get_risk_level_dns(results['dns'])]
    ]
    
    summary_table = Table(summary_data, colWidths=[2.2*inch, 1.2*inch, 1.2*inch, 1.2*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2563eb')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 11),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('TOPPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8fafc')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
        ('FONTSIZE', (0, 1), (-1, -1), 10),
        ('TOPPADDING', (0, 1), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 8),
    ]))
    
    story.append(summary_table)
    story.append(PageBreak())
    
    # ========================================================================
    # DETAILED FINDINGS (Enhanced with more info and fixes)
    # ========================================================================
    
    story.append(Paragraph("Detailed Security Analysis", styles['Heading1']))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e2e8f0')))
    story.append(Spacer(1, 0.2*inch))
    
    # Port Security (Enhanced)
    story.extend(create_enhanced_port_section(results['ports'], styles))
    story.append(Spacer(1, 0.4*inch))
    
    # SSL/TLS (Enhanced)
    story.extend(create_enhanced_ssl_section(results['ssl'], styles))
    story.append(Spacer(1, 0.4*inch))
    
    # HTTP Headers (Enhanced)
    story.extend(create_enhanced_headers_section(results['headers'], styles))
    story.append(PageBreak())
    
    # DNS (Enhanced)
    story.extend(create_enhanced_dns_section(results['dns'], styles))
    story.append(PageBreak())
    
    # ========================================================================
    # RECOMMENDATIONS (NEW - Not on website)
    # ========================================================================
    
    story.append(Paragraph("Prioritized Recommendations", styles['Heading1']))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e2e8f0')))
    story.append(Spacer(1, 0.2*inch))
    
    recommendations = generate_recommendations(results)
    
    for i, rec in enumerate(recommendations, 1):
        # Priority header
        priority_color = colors.HexColor('#ef4444') if rec['priority'] == 'Critical' else \
                        colors.HexColor('#f59e0b') if rec['priority'] == 'High' else \
                        colors.HexColor('#3b82f6')
        
        priority_style = ParagraphStyle(
            f'Priority{i}',
            parent=styles['Heading3'],
            textColor=priority_color,
            spaceAfter=8
        )
        
        story.append(Paragraph(f"{i}. [{rec['priority']}] {rec['title']}", priority_style))
        story.append(Spacer(1, 0.12*inch))
        
        # Issue description
        story.append(Paragraph(f"<b>Issue:</b> {rec['issue']}", body_style))
        story.append(Spacer(1, 0.1*inch))
        
        # Impact
        story.append(Paragraph(f"<b>Impact:</b> {rec['impact']}", body_style))
        story.append(Spacer(1, 0.15*inch))
        
        # Fix (the valuable part!)
        story.append(Paragraph(f"<b>How to Fix:</b>", body_style))
        story.append(Spacer(1, 0.15*inch))
        
        fix_style = ParagraphStyle(
            'FixStyle',
            parent=styles['Normal'],
            leftIndent=15,
            rightIndent=15,
            fontName='Courier',
            fontSize=10,
            leading=14,
            textColor=colors.HexColor('#047857'),
            backColor=colors.HexColor('#d1fae5'),
            borderPadding=15,
            borderColor=colors.HexColor('#059669'),
            borderWidth=1,
        )
        
        story.append(Paragraph(rec['fix'], fix_style))
        story.append(Spacer(1, 0.3*inch))
    
    # ========================================================================
    # CONCLUSION
    # ========================================================================
    
    story.append(PageBreak())
    story.append(Paragraph("Conclusion", styles['Heading1']))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e2e8f0')))
    story.append(Spacer(1, 0.2*inch))
    
    conclusion = generate_conclusion(score, results)
    story.append(Paragraph(conclusion, normal_justified))
    
    story.append(Spacer(1, 0.4*inch))
    
    # Next steps
    story.append(Paragraph("Next Steps", styles['Heading2']))
    story.append(Spacer(1, 0.1*inch))
    
    next_steps = f"""
    1. <b>Immediate Action:</b> Address all Critical and High priority issues within 24-48 hours<br/>
    2. <b>Short Term (1 week):</b> Implement Medium priority recommendations<br/>
    3. <b>Long Term (1 month):</b> Review and implement Low priority suggestions<br/>
    4. <b>Ongoing:</b> Re-scan your domain monthly to ensure continued security
    """
    
    story.append(Paragraph(next_steps, body_style))
    
    story.append(Spacer(1, 0.5*inch))
    
    # Footer
    footer = """
    <i>This report was generated by SecCheck automated security scanner. 
    While comprehensive, this scan does not replace professional penetration testing 
    or manual security audits. For critical infrastructure, we recommend engaging 
    security professionals for in-depth assessment.</i>
    """
    
    footer_style = ParagraphStyle(
        'Footer',
        parent=styles['Normal'],
        fontSize=9,
        textColor=colors.grey,
        alignment=TA_JUSTIFY
    )
    
    story.append(Paragraph(footer, footer_style))
    
    # ========================================================================
    # BUILD PDF
    # ========================================================================
    
    doc.build(story, onFirstPage=add_page_number, onLaterPages=add_page_number)
    
    print(f"  ✓ PDF report generated: {filename}")
    print("return filepath:", filepath)
    return filepath


def add_page_number(canvas, doc):
    """Add page number to the footer"""
    page_num = canvas.getPageNumber()
    text = f"Page {page_num}"
    canvas.setFont('Helvetica', 9)
    canvas.setFillColor(colors.grey)
    canvas.drawRightString(7.5*inch, 0.5*inch, text)


# ============================================================================
# ENHANCED HELPER FUNCTIONS
# ============================================================================

def get_risk_assessment(score, score_data):
    """Generate risk assessment paragraph based on score"""
    if score >= 90:
        return """Your website demonstrates <b>excellent security posture</b>. The identified issues 
        are minor and do not pose immediate risk. Continue maintaining your security standards 
        and address the recommendations to achieve perfect security."""
    elif score >= 80:
        return """Your website has <b>good security</b> with some areas for improvement. The identified 
        issues should be addressed to prevent potential vulnerabilities, but none pose immediate 
        critical risk."""
    elif score >= 70:
        return """Your website has <b>fair security</b> with several areas requiring attention. 
        Some of the identified issues could be exploited by attackers and should be prioritized 
        for remediation."""
    elif score >= 60:
        return """Your website has <b>poor security</b> with multiple vulnerabilities that require 
        immediate attention. These issues significantly increase your risk of being compromised."""
    else:
        return """Your website has <b>critical security deficiencies</b> that require urgent remediation. 
        The identified vulnerabilities leave your site highly exposed to attacks. Immediate action 
        is required to protect your data and users."""

def count_high_risk_issues(results):
    """Count critical and high severity issues"""
    count = 0
    
    # Risky ports
    count += len(results['ports'].get('risky_ports', []))
    
    # SSL issues
    if not results['ssl'].get('has_ssl'):
        count += 1
    elif not results['ssl'].get('valid'):
        count += 1
    
    # High risk headers
    for header in results['headers'].get('missing_headers', []):
        if header['risk'] == 'High':
            count += 1
    
    # High severity DNS
    for issue in results['dns'].get('issues', []):
        if issue['severity'] in ['Critical', 'High']:
            count += 1
    
    return count

def count_medium_risk_issues(results):
    """Count medium severity issues"""
    count = 0
    
    # Medium risk headers
    for header in results['headers'].get('missing_headers', []):
        if header['risk'] == 'Medium':
            count += 1
    
    # Medium severity DNS
    for issue in results['dns'].get('issues', []):
        if issue['severity'] == 'Medium':
            count += 1
    
    return count

def count_low_risk_issues(results):
    """Count low severity issues"""
    count = 0
    
    # Low risk headers
    for header in results['headers'].get('missing_headers', []):
        if header['risk'] == 'Low':
            count += 1
    
    # Low severity DNS
    for issue in results['dns'].get('issues', []):
        if issue['severity'] == 'Low':
            count += 1
    
    return count

def get_status_icon(results):
    """Get status icon for table"""
    has_issues = bool(results.get('issues', []) or results.get('risky_ports', []) or 
                     results.get('missing_headers', []) or not results.get('valid', True))
    return "⚠" if has_issues else "✓"

def get_risk_level_ports(results):
    """Get risk level for ports"""
    risky = len(results.get('risky_ports', []))
    if risky > 0:
        return "High"
    elif len(results.get('open_ports', [])) > 5:
        return "Low"
    return "Minimal"

def get_risk_level_ssl(results):
    """Get risk level for SSL"""
    if not results.get('has_ssl'):
        return "Critical"
    elif not results.get('valid'):
        return "High"
    elif results.get('days_remaining', 999) < 30:
        return "Medium"
    return "Minimal"

def get_risk_level_headers(results):
    """Get risk level for headers"""
    high_risk = sum(1 for h in results.get('missing_headers', []) if h['risk'] == 'High')
    if high_risk >= 2:
        return "High"
    elif high_risk == 1:
        return "Medium"
    elif results.get('missing_headers'):
        return "Low"
    return "Minimal"

def get_risk_level_dns(results):
    """Get risk level for DNS"""
    for issue in results.get('issues', []):
        if issue['severity'] in ['Critical', 'High']:
            return "High"
    if results.get('issues'):
        return "Low"
    return "Minimal"

def count_port_issues(results):
    return str(len(results.get('risky_ports', [])))

def count_ssl_issues(results):
    if not results.get('has_ssl'):
        return "1"
    return str(len(results.get('errors', [])))

def count_header_issues(results):
    return str(len(results.get('missing_headers', [])))

def count_dns_issues(results):
    return str(len(results.get('issues', [])))


# ============================================================================
# ENHANCED SECTION CREATORS
# ============================================================================

def create_enhanced_port_section(port_data, styles):
    """Enhanced port security section with more details"""
    elements = []
    
    section_header = ParagraphStyle(
        'SectionHeader',
        parent=styles['Heading2'],
        fontSize=18,
        textColor=colors.HexColor('#2563eb'),
        spaceAfter=15,
        spacingBefore=10
    )
    
    elements.append(Paragraph("🔌 Network Port Security Analysis", section_header))
    
    open_ports = port_data.get('open_ports', [])
    risky_ports = port_data.get('risky_ports', [])
    
    # Overview
    overview = f"""
    <b>Scan Summary:</b><br/>
    • Total Ports Scanned: {port_data.get('total_scanned', 6)}<br/>
    • Open Ports Detected: {len(open_ports)}<br/>
    • Risky Ports Found: {len(risky_ports)}<br/>
    • IP Address: {port_data.get('ip_address', 'N/A')}
    """
    
    elements.append(Paragraph(overview, styles['Normal']))
    elements.append(Spacer(1, 0.2*inch))
    
    # What this means
    if risky_ports:
        insight = f"""
        <b>Security Insight:</b> {len(risky_ports)} risky port(s) detected that should typically 
        not be exposed to the public internet. These ports provide attack vectors that malicious 
        actors could exploit to gain unauthorized access to your systems.
        """
        elements.append(Paragraph(insight, styles['Normal']))
        elements.append(Spacer(1, 0.15*inch))
    
    # Open ports details
    if open_ports:
        elements.append(Paragraph("<b>Open Ports Details:</b>", styles['Heading4']))
        
        port_table_data = [['Port', 'Service', 'Risk Level']]
        
        for port_info in open_ports:
            is_risky = any(r['port'] == port_info['port'] for r in risky_ports)
            risk = "⚠ High" if is_risky else "✓ Normal"
            port_table_data.append([
                str(port_info['port']),
                port_info['service'],
                risk
            ])
        
        port_table = Table(port_table_data, colWidths=[1*inch, 2.5*inch, 1.5*inch])
        port_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e2e8f0')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        
        elements.append(port_table)
        elements.append(Spacer(1, 0.2*inch))
    
    # Risky ports with fixes
    if risky_ports:
        elements.append(Paragraph("<b>⚠ Critical Findings - Risky Ports:</b>", styles['Heading4']))
        
        for risky in risky_ports:
            finding = f"""
            <b>Port {risky['port']} ({risky['service']}):</b><br/>
            <i>Risk: {risky.get('risk', 'High')}</i><br/>
            {risky['reason']}
            """
            elements.append(Paragraph(finding, styles['Normal']))
            elements.append(Spacer(1, 0.1*inch))
    
    return elements
def create_enhanced_ssl_section(ssl_data, styles):
    """Enhanced SSL section"""
    elements = []
    
    section_header = ParagraphStyle(
        'SectionHeader',
        parent=styles['Heading2'],
        textColor=colors.HexColor('#1e293b'),
        spaceAfter=15
    )
    
    elements.append(Paragraph("🔒 SSL/TLS Certificate Analysis", section_header))
    
    if not ssl_data.get('has_ssl'):
        warning = """
        <b>CRITICAL FINDING:</b> This website does not use HTTPS encryption. All data transmitted 
        between users and the server is sent in plain text, making it vulnerable to interception, 
        man-in-the-middle attacks, and data theft. This also negatively impacts SEO rankings as 
        search engines prioritize HTTPS sites.
        """
        elements.append(Paragraph(warning, styles['Normal']))
    else:
        status = "✓ Valid and Secure" if ssl_data.get('valid') else "⚠ Issues Detected"
        
        cert_info = f"""
        <b>Certificate Status:</b> {status}<br/>
        <b>Issuing Authority:</b> {ssl_data.get('issuer', 'Unknown')}<br/>
        <b>Expiration Date:</b> {ssl_data.get('expires', 'Unknown')}<br/>
        <b>Days Until Expiration:</b> {ssl_data.get('days_remaining', 'Unknown')} days<br/>
        """
        
        elements.append(Paragraph(cert_info, styles['Normal']))
        elements.append(Spacer(1, 0.15*inch))
        
        # Expiration warning
        days_left = ssl_data.get('days_remaining')
        if days_left and days_left < 30:
            expiry_warning = f"""
            <b>⚠ WARNING:</b> Your SSL certificate expires in {days_left} days. Certificates should 
            be renewed at least 30 days before expiration to prevent service disruption.
            """
            elements.append(Paragraph(expiry_warning, styles['Normal']))
            elements.append(Spacer(1, 0.15*inch))
        
        # Errors
        errors = ssl_data.get('errors', [])
        if errors:
            elements.append(Paragraph("<b>Certificate Issues:</b>", styles['Heading4']))
            for error in errors:
                elements.append(Paragraph(f"• {error}", styles['Normal']))
    
    return elements

def create_enhanced_headers_section(header_data, styles):
    """Enhanced headers section"""
    elements = []
    
    section_header = ParagraphStyle(
        'SectionHeader',
        parent=styles['Heading2'],
        textColor=colors.HexColor('#1e293b'),
        spaceAfter=15
    )
    
    elements.append(Paragraph("🛡️ HTTP Security Headers Analysis", section_header))
    
    present = header_data.get('present_headers', [])
    missing = header_data.get('missing_headers', [])
    
    summary = f"""
    <b>Header Configuration:</b><br/>
    • Security Headers Implemented: {len(present)}/6<br/>
    • Missing Security Headers: {len(missing)}
    """
    
    elements.append(Paragraph(summary, styles['Normal']))
    elements.append(Spacer(1, 0.2*inch))
    
    # What this means
    if missing:
        high_risk_missing = [h for h in missing if h['risk'] == 'High']
        if high_risk_missing:
            insight = f"""
            <b>Security Insight:</b> {len(high_risk_missing)} critical security header(s) are missing. 
            These headers provide essential protection against common web attacks like Cross-Site 
            Scripting (XSS), clickjacking, and other injection attacks.
            """
            elements.append(Paragraph(insight, styles['Normal']))
            elements.append(Spacer(1, 0.15*inch))
    
    # Present headers
    if present:
        elements.append(Paragraph("<b>✓ Implemented Headers:</b>", styles['Heading4']))
        for header in present:
            header_text = f"• <b>{header['name']}</b>: {header['description']}"
            elements.append(Paragraph(header_text, styles['Normal']))
        elements.append(Spacer(1, 0.2*inch))
    
    # Missing headers
    if missing:
        elements.append(Paragraph("<b>⚠ Missing Security Headers:</b>", styles['Heading4']))
        
        for header in missing:
            risk_color = '#ef4444' if header['risk'] == 'High' else '#f59e0b' if header['risk'] == 'Medium' else '#3b82f6'
            
            header_text = f"""
            <b>{header['name']}</b> [<font color="{risk_color}">{header['risk']} Risk</font>]<br/>
            <i>{header['description']}</i>
            """
            elements.append(Paragraph(header_text, styles['Normal']))
            elements.append(Spacer(1, 0.1*inch))
    
    return elements

def create_enhanced_dns_section(dns_data, styles):
    """Enhanced DNS section"""
    elements = []
    
    section_header = ParagraphStyle(
        'SectionHeader',
        parent=styles['Heading2'],
        textColor=colors.HexColor('#1e293b'),
        spaceAfter=15
    )
    
    elements.append(Paragraph("🌐 DNS Configuration Analysis", section_header))
    
    # Overview
    overview = f"""
    <b>DNS Infrastructure:</b><br/>
    • IP Addresses (A Records): {len(dns_data.get('a_records', []))}<br/>
    • Mail Servers (MX Records): {len(dns_data.get('mx_records', []))}<br/>
    • Nameservers (NS Records): {len(dns_data.get('ns_records', []))}<br/>
    • SPF Email Authentication: {'✓ Configured' if dns_data.get('has_spf') else '✗ Not Found'}
    """
    
    elements.append(Paragraph(overview, styles['Normal']))
    elements.append(Spacer(1, 0.2*inch))
    
    # IP addresses
    if dns_data.get('a_records'):
        elements.append(Paragraph("<b>IP Address(es):</b>", styles['Heading4']))
        for ip in dns_data.get('a_records', []):
            elements.append(Paragraph(f"• {ip}", styles['Normal']))
        elements.append(Spacer(1, 0.15*inch))
    
    # Nameservers
    if dns_data.get('ns_records'):
        elements.append(Paragraph("<b>Authoritative Nameservers:</b>", styles['Heading4']))
        for ns in dns_data.get('ns_records', []):
            elements.append(Paragraph(f"• {ns}", styles['Normal']))
        elements.append(Spacer(1, 0.15*inch))
    
    # Email configuration
    if dns_data.get('mx_records'):
        elements.append(Paragraph("<b>Mail Server Configuration:</b>", styles['Heading4']))
        for mx in dns_data.get('mx_records', []):
            mx_text = f"• {mx['server']} (Priority: {mx['priority']})"
            elements.append(Paragraph(mx_text, styles['Normal']))
        elements.append(Spacer(1, 0.15*inch))
    
    # Issues
    issues = dns_data.get('issues', [])
    if issues:
        elements.append(Paragraph("<b>⚠ Configuration Issues:</b>", styles['Heading4']))
        
        for issue in issues:
            risk_color = '#ef4444' if issue['severity'] == 'High' else '#f59e0b' if issue['severity'] == 'Medium' else '#3b82f6'
            
            issue_text = f"""
            <b>[<font color="{risk_color}">{issue['severity']}</font>]</b> {issue['message']}
            """
            elements.append(Paragraph(issue_text, styles['Normal']))
            elements.append(Spacer(1, 0.1*inch))
    
    return elements


# ============================================================================
# RECOMMENDATIONS GENERATOR
# ============================================================================

def generate_recommendations(results):
    """Generate prioritized recommendations with fixes"""
    recommendations = []
    
    # SSL recommendations
    if not results['ssl'].get('has_ssl'):
        recommendations.append({
            'priority': 'Critical',
            'title': 'Enable HTTPS Encryption',
            'issue': 'Website does not use SSL/TLS encryption',
            'impact': 'All data transmitted is vulnerable to interception. Users cannot trust your site. Search engines will penalize your rankings.',
            'fix': """
1. Obtain an SSL certificate (free from Let's Encrypt recommended)
2. Install certificate on your web server
3. Configure server to redirect all HTTP traffic to HTTPS

For Apache:
    RewriteEngine On
    RewriteCond %{HTTPS} off
    RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]

For Nginx:
    server {
        listen 80;
        return 301 https://$host$request_uri;
    }
            """
        })
    
    # Risky ports
    risky_ports = results['ports'].get('risky_ports', [])
    if risky_ports:
        port_numbers = ', '.join(str(p['port']) for p in risky_ports)
        recommendations.append({
            'priority': 'Critical',
            'title': f'Close Exposed Risky Ports ({port_numbers})',
            'issue': f'{len(risky_ports)} sensitive port(s) exposed to public internet',
            'impact': 'Attackers can directly access your database, remote access services, or other sensitive systems.',
            'fix': f"""
Use firewall rules to block these ports from public access:

For UFW (Ubuntu):
    sudo ufw deny {risky_ports[0]['port']}/tcp

For iptables:
    sudo iptables -A INPUT -p tcp --dport {risky_ports[0]['port']} -j DROP

For cloud providers (AWS/Azure/GCP):
    Update security group rules to remove public access to these ports
            """
        })
    
    # Missing critical headers
    critical_headers = [h for h in results['headers'].get('missing_headers', []) if h['risk'] == 'High']
    if critical_headers:
        header_names = ', '.join(h['name'] for h in critical_headers[:2])
        recommendations.append({
            'priority': 'High',
            'title': f'Implement Critical Security Headers',
            'issue': f'{len(critical_headers)} critical security header(s) missing',
            'impact': 'Website vulnerable to XSS attacks, clickjacking, and other injection attacks.',
            'fix': """
Add these headers to your web server configuration:

For Apache (.htaccess or httpd.conf):
    Header set Content-Security-Policy "default-src 'self'"
    Header set X-Frame-Options "SAMEORIGIN"
    Header set Strict-Transport-Security "max-age=31536000"

For Nginx:
    add_header Content-Security-Policy "default-src 'self'";
    add_header X-Frame-Options "SAMEORIGIN";
    add_header Strict-Transport-Security "max-age=31536000";
            """
        })
    
    # DNS issues
    high_dns_issues = [i for i in results['dns'].get('issues', []) if i['severity'] == 'High']
    if high_dns_issues:
        recommendations.append({
            'priority': 'High',
            'title': 'Fix DNS Configuration Issues',
            'issue': high_dns_issues[0]['message'],
            'impact': 'DNS failures can make your website completely inaccessible.',
            'fix': """
            Contact your DNS provider or hosting company to:
            1. Add a second nameserver for redundancy
            2. Ensure all nameservers are responding correctly
            3. Verify DNS propagation globally
            """
            })
        
        # Email security
    if results['dns'].get('mx_records') and not results['dns'].get('has_spf'):
        recommendations.append({
            'priority': 'Medium',
            'title': 'Configure SPF Email Authentication',
            'issue': 'No SPF record found - emails can be spoofed',
            'impact': 'Attackers can send emails pretending to be from your domain. Your legitimate emails may be marked as spam.',
            'fix': """
        Add SPF TXT record to your DNS:

        Record Type: TXT
        Host: @
        Value: v=spf1 include:_spf.your-email-provider.com ~all

        Common providers:
        - Google Workspace: v=spf1 include:_spf.google.com ~all
        - Microsoft 365: v=spf1 include:spf.protection.outlook.com ~all
        - SendGrid: v=spf1 include:sendgrid.net ~all
            """
            })
        
        # Certificate expiration
    days_left = results['ssl'].get('days_remaining')
    if days_left and days_left < 30:
        recommendations.append({
            'priority': 'Medium',
            'title': 'Renew SSL Certificate',
            'issue': f'SSL certificate expires in {days_left} days',
            'impact': 'When certificate expires, browsers will show scary warnings to all visitors.',
            'fix': """
        Renew certificate immediately:

For Let's Encrypt (certbot):
        sudo certbot renew

For commercial certificates:
        1. Contact your certificate provider
        2. Generate new CSR
        3. Complete validation
        4. Install new certificate

Set up automatic renewal to prevent future issues.
            """
            })
    return recommendations

def generate_conclusion(score, results):
    """Generate conclusion based on findings"""
    
    if score >= 90:
        return """
        Overall, your website demonstrates strong security practices. The few identified issues 
        are minor and easily addressable. Continue monitoring your security posture regularly 
        and stay informed about emerging threats. Consider implementing the low-priority 
        recommendations when resources permit to achieve optimal security.
        """
    elif score >= 70:
        return """
        Your website has a solid security foundation, but there are several areas that require 
        improvement. Focus on implementing the high-priority recommendations first, as these 
        address the most significant vulnerabilities. With these improvements, your site will 
        have significantly better protection against common attacks.
        """
    elif score >= 50:
        return """
        Your website has multiple security vulnerabilities that need immediate attention. 
        The identified issues leave your site vulnerable to various attack vectors. Prioritize 
        implementing the critical and high-priority recommendations within the next 1-2 weeks. 
        Consider engaging a security professional for a comprehensive security audit.
        """
    else:
        return """
        Your website has serious security deficiencies that require urgent remediation. The current 
        state leaves your site highly vulnerable to attacks, potentially risking user data, 
        reputation, and compliance violations. We strongly recommend treating this as a critical 
        priority and implementing all high and critical recommendations immediately. Consider 
        engaging professional security services for comprehensive hardening.
        """


# Test the enhanced PDF
if __name__ == '__main__':
    # More realistic test data
    test_results = {
        'domain': 'example.com',
        'score': {
            'score': 72,
            'rating': 'C',
            'status': 'Fair',
            'total_issues': 5,
            'breakdown': {
                'ports': 0,
                'ssl': 0,
                'headers': 16,
                'dns': 1
            }
        },
        'ports': {
            'open_ports': [
                {'port': 80, 'service': 'HTTP (Website)'},
                {'port': 443, 'service': 'HTTPS (Secure Website)'}
            ],
            'risky_ports': [],
            'total_scanned': 6,
            'ip_address': '93.184.216.34'
        },
        'ssl': {
            'has_ssl': True,
            'valid': True,
            'issuer': 'DigiCert Inc',
            'expires': '2025-12-31',
            'days_remaining': 308,
            'errors': []
        },
        'headers': {
            'present_headers': [
                {'name': 'X-Frame-Options', 'description': 'Prevents clickjacking'}
            ],
            'missing_headers': [
                {'name': 'Content-Security-Policy', 'risk': 'High', 'description': 'Prevents XSS attacks'},
                {'name': 'Strict-Transport-Security', 'risk': 'High', 'description': 'Forces HTTPS'},
                {'name': 'Referrer-Policy', 'risk': 'Low', 'description': 'Controls referrer info'}
            ]
        },
        'dns': {
            'a_records': ['93.184.216.34'],
            'mx_records': [
                {'server': 'mail.example.com', 'priority': 10}
            ],
            'ns_records': ['ns1.example.com', 'ns2.example.com'],
            'has_spf': False,
            'issues': [
                {'severity': 'Medium', 'message': 'No SPF record found - emails may be spoofed'}
            ]
        }
    }
    
    pdf_path = generate_pdf_report(test_results)
    print(f"\n✓ Enhanced PDF created at: {pdf_path}")
    print("Open it to see the improvements!")
