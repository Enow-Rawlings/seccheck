from flask import Flask
from flask_mail import Mail, Message
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASS')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('EMAIL_USER')

mail = Mail(app)

print("Testing email configuration...")
print(f"Email User: {os.environ.get('EMAIL_USER')}")
print(f"Email Pass: {'*' * len(os.environ.get('EMAIL_PASS', ''))} (hidden)")

with app.app_context():
    try:
        msg = Message(
            subject="SecCheck Test Email",
            recipients=[os.environ.get('EMAIL_USER')]  # Send to yourself
        )
        msg.body = "If you receive this, email is configured correctly!"
        
        mail.send(msg)
        print("✓ Test email sent successfully!")
        print(f"Check your inbox: {os.environ.get('EMAIL_USER')}")
    except Exception as e:
        print(f"✗ Error: {str(e)}")
