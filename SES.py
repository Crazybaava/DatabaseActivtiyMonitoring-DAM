from datetime import date, timedelta
import os
import boto3
import email.mime.multipart
import email.mime.text
import email.mime.application
import base64

def send_report_via_ses(sender, recipients, subject, attachment_filepath, region_name):
    Report_Date = date.today()-timedelta(days=1)
    if not recipients or not os.path.exists(attachment_filepath):
        print("Error: No recipients or attachment file not found.")
        return

    msg = email.mime.multipart.MIMEMultipart()
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = ", ".join(recipients) 

    text = f"Hi Team,\n\nPlease find the attached Daily Database Activity Monitoring (DAM) Report.\n\nReport generated for: {Report_Date}.\n\nOpen the attached file '{os.path.basename(attachment_filepath)}' in a web browser for the full interactive view."
    part = email.mime.text.MIMEText(text, 'plain')
    msg.attach(part)

    with open(attachment_filepath, 'rb') as f:
        attachment_part = email.mime.application.MIMEApplication(f.read(), _subtype='html')
        
    attachment_part.add_header(
        'Content-Disposition', 
        'attachment', 
        filename=os.path.basename(attachment_filepath)
    )
    msg.attach(attachment_part)
    
    try:
        ses_client = boto3.client('ses', region_name=region_name)

        response = ses_client.send_raw_email(
            Source=sender,
            Destinations=recipients, # SES requires a list for destinations
            RawMessage={'Data': msg.as_string()} # Pass the entire MIME structure as a string
        )
        print(f"Email sent successfully with attachment! Message ID: {response['MessageId']}")

    except Exception as e:
        print(f"Error sending email via SES: {e}")
        print("Please ensure your SENDER_EMAIL is verified and your IAM user has the 'ses:SendRawEmail' permission.")

