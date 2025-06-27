import os
import logging
from datetime import datetime
from random import Random
import requests
import base64
import json

from flask import Flask, render_template, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

import boto3
from botocore.exceptions import ClientError

from dotenv import load_dotenv

load_dotenv()

class Config:
    MAX_CONTENT_LENGTH = 15 * 1024 * 1024  # 15 MB
    EMAIL_DOMAIN = "@ethereum.org"
    DEFAULT_RECIPIENT_EMAIL = "kyc@ethereum.org"
    NUMBER_OF_ATTACHMENTS = int(os.getenv('NUMBEROFATTACHMENTS', 10))
    SECRET_KEY = os.getenv('SECRET_KEY', 'you-should-set-a-secret-key')

def validate_env_vars(required_vars):
    """
    Validates that all required environment variables are set.
    """
    missing_vars = [var for var in required_vars if var not in os.environ]
    if missing_vars:
        raise EnvironmentError(f"Missing required environment variables: {', '.join(missing_vars)}")

def sanitize_filename(filename):
    """
    Sanitizes the filename to prevent directory traversal and other issues.
    """
    return filename.replace("..", "").replace("/", "").replace("\\", "")

def parse_form(form):
    """
    Parses the form data to extract the message, recipient, reference, and attachments.
    """
    text = form['message']
    recipient = form['recipient']
    reference = form.get('reference', '')

    all_attachments = []
    for i in range(Config.NUMBER_OF_ATTACHMENTS):
        attachment = form.get(f'attachment-{i}')
        filename = form.get(f'filename-{i}', '').encode('ascii', 'ignore').decode()  # remove non-ascii characters
        if not attachment:
            continue
        sanitized_filename = sanitize_filename(filename)
        all_attachments.append((sanitized_filename, attachment))
    return text, recipient, reference, all_attachments

def valid_recipient(recipient):
    """
    Checks if the recipient is valid.
    """
    valid_recipients = ['legal', 'devcon', 'security']
    return recipient in valid_recipients

def get_identifier(recipient, now=None, randint=None):
    """
    Generates a unique identifier based on the recipient, current timestamp, and a random number.
    """
    if now is None:
        now = datetime.now()
    if randint is None:
        randint = Random().randint(1000, 9999)
    return f'{recipient}:{now.strftime("%Y:%m:%d:%H:%M:%S")}:{randint}'

def create_email(to_email, identifier, text, all_attachments, reference=''):
    """
    Creates an email message with attachments for AWS SES.
    """
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    from email.mime.application import MIMEApplication
    
    plain_text = text.replace('<br />', '\n')
    subject = f'Secure Form Submission {identifier}'
    if reference:
        subject = f'{reference} {subject}'
    
    # Create message container
    msg = MIMEMultipart()
    msg['Subject'] = subject
    msg['From'] = FROMEMAIL
    msg['To'] = to_email
    
    # Add body to email
    body = MIMEText(plain_text, 'plain')
    msg.attach(body)
    
    # Add attachments
    for item in all_attachments:
        filename = item['filename']
        attachment_content = item['attachment']
        
        # Create attachment
        part = MIMEApplication(attachment_content.encode('utf-8'))
        part.add_header(
            'Content-Disposition',
            'attachment',
            filename=f'{filename}.pgp'
        )
        msg.attach(part)
    
    return msg

def validate_turnstile(turnstile_response):
    """
    Validates the Turnstile response using Cloudflare's API.
    """
    secret_key = os.getenv('TURNSTILE_SECRET_KEY')
    payload = {
        'secret': secret_key,
        'response': turnstile_response
    }
    response = requests.post('https://challenges.cloudflare.com/turnstile/v0/siteverify', data=payload)
    result = response.json()

    # Log the validation result
    logging.info(f"Turnstile validation response: {result}")

    if not result.get('success'):
        error_codes = result.get('error-codes', [])
        logging.error(f"Turnstile verification failed with error codes: {error_codes}")
        raise ValueError('Turnstile verification failed.')

def send_email(message):
    """
    Sends the email using AWS SES and logs detailed information for debugging.
    """
    try:
        # Send the email
        response = ses_client.send_raw_email(
            Source=message['From'],
            Destinations=[message['To']],
            RawMessage={
                'Data': message.as_string()
            }
        )
        
        # Log the response
        message_id = response['MessageId']
        logging.info('AWS SES email sent successfully. MessageId: %s', message_id)
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        logging.error('AWS SES error: Code=%s, Message=%s', error_code, error_message)
        
        # Provide user-friendly error messages
        if error_code == 'MessageRejected':
            raise ValueError('Error: Email was rejected by AWS SES. Please check the email configuration.')
        elif error_code == 'MailFromDomainNotVerified':
            raise ValueError('Error: The sender email domain is not verified in AWS SES.')
        elif error_code == 'ConfigurationSetDoesNotExist':
            raise ValueError('Error: AWS SES configuration error.')
        else:
            raise ValueError(f'Error: Failed to send email. {error_message}')
            
    except Exception as e:
        logging.error('Error sending email via AWS SES: %s', str(e))
        raise


def get_forwarded_address():
    # Check X-Forwarded-For header first
    forwarded_for = request.headers.get('X-Forwarded-For')
    if forwarded_for:
        # Return the leftmost IP which is the original client IP
        return forwarded_for.split(',')[0].strip()
    
    # Fall back to X-Real-IP if available
    real_ip = request.headers.get('X-Real-IP')
    if real_ip:
        return real_ip
    
    # Otherwise use the default function
    return get_remote_address()

def find_aog_item_by_grant_id(grant_id):
    """
    Finds an AOG (Approval of Grants) item in Kissflow by Grant ID.
    Returns the item ID if found, None otherwise.
    """
    try:
        api_key = os.getenv('KISSFLOW_API_KEY')
        account_id = os.getenv('KISSFLOW_ACCOUNT_ID')
        process_id = os.getenv('KISSFLOW_PROCESS_ID')
        
        if not all([api_key, account_id, process_id]):
            logging.error("Missing Kissflow configuration")
            return None
        
        # Kissflow API endpoint to search for items
        url = f"https://api.kissflow.com/api/v1/accounts/{account_id}/processes/{process_id}/items"
        
        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }
        
        # Search for items with matching Grant ID in Request_number field
        params = {
            'filter': f'Request_number eq "{grant_id}"',
            'limit': 1
        }
        
        response = requests.get(url, headers=headers, params=params)
        
        if response.status_code == 200:
            data = response.json()
            items = data.get('data', [])
            if items:
                return items[0].get('_id')
        else:
            logging.error(f"Kissflow API error: {response.status_code} - {response.text}")
            
    except Exception as e:
        logging.error(f"Error finding AOG item: {str(e)}")
    
    return None

def update_aog_kyc_comments(item_id, legal_identifier):
    """
    Updates the KYC_Comments field in a Kissflow AOG item with the legal identifier.
    """
    try:
        api_key = os.getenv('KISSFLOW_API_KEY')
        account_id = os.getenv('KISSFLOW_ACCOUNT_ID')
        process_id = os.getenv('KISSFLOW_PROCESS_ID')
        
        if not all([api_key, account_id, process_id]):
            logging.error("Missing Kissflow configuration")
            return False
        
        # Kissflow API endpoint to update an item
        url = f"https://api.kissflow.com/api/v1/accounts/{account_id}/processes/{process_id}/items/{item_id}"
        
        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }
        
        # Update the KYC_Comments field
        payload = {
            'KYC_Comments': legal_identifier
        }
        
        response = requests.patch(url, headers=headers, json=payload)
        
        if response.status_code in [200, 204]:
            logging.info(f"Successfully updated AOG item {item_id} with legal identifier {legal_identifier}")
            return True
        else:
            logging.error(f"Kissflow API error: {response.status_code} - {response.text}")
            
    except Exception as e:
        logging.error(f"Error updating AOG item: {str(e)}")
    
    return False

def send_identifier_to_kissflow(grant_id, legal_identifier):
    """
    Sends the legal identifier to the Kissflow AOG item based on Grant ID.
    """
    if not grant_id:
        logging.warning("No Grant ID provided, skipping Kissflow update")
        return False
    
    # Find the AOG item by Grant ID
    item_id = find_aog_item_by_grant_id(grant_id)
    
    if not item_id:
        logging.warning(f"No AOG item found for Grant ID: {grant_id}")
        return False
    
    # Update the KYC_Comments field
    success = update_aog_kyc_comments(item_id, legal_identifier)
    
    return success

# Validate required environment variables
required_env_vars = ['TURNSTILE_SITE_KEY', 'TURNSTILE_SECRET_KEY', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_REGION', 'SES_FROM_EMAIL']
validate_env_vars(required_env_vars)

TURNSTILE_SITE_KEY = os.environ['TURNSTILE_SITE_KEY']
TURNSTILE_SECRET_KEY = os.environ['TURNSTILE_SECRET_KEY']
AWS_ACCESS_KEY_ID = os.environ['AWS_ACCESS_KEY_ID']
AWS_SECRET_ACCESS_KEY = os.environ['AWS_SECRET_ACCESS_KEY']
AWS_REGION = os.environ['AWS_REGION']
FROMEMAIL = os.environ['SES_FROM_EMAIL']

# Initialize AWS SES client
ses_client = boto3.client(
    'ses',
    region_name=AWS_REGION,
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY
)

app = Flask(__name__)
app.config.from_object(Config)



# Initialize rate limiting
limiter = Limiter(get_forwarded_address, app=app, default_limits=["200 per day", "50 per hour"])

# Configure logging
log_file = os.environ.get('LOG_FILE', '')
if log_file:
    logging.basicConfig(filename=log_file, level=logging.INFO)
else:
    logging.basicConfig(level=logging.INFO)

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html', notice='', hascaptcha=True, attachments_number=Config.NUMBER_OF_ATTACHMENTS, turnstile_sitekey=TURNSTILE_SITE_KEY)

@app.route('/submit-encrypted-data', methods=['POST'])
@limiter.limit("3 per minute")
def submit():
    try:
        # Parse JSON data from request
        data = request.get_json()

        # Validate Turnstile
        turnstile_response = data.get('cf-turnstile-response', '')
        if not turnstile_response:
            logging.warning(f"Missing Turnstile response. Potential bypass attempt detected from IP: {request.remote_addr}")
            return jsonify({'status': 'failure', 'message': 'Missing Turnstile token'}), 400

        try:
            validate_turnstile(turnstile_response)
        except ValueError as e:
            return jsonify({'status': 'failure', 'message': str(e)}), 400

        message = data['message']
        recipient = data['recipient']
        reference = data.get('reference', '')
        files = data['files']

        if not valid_recipient(recipient):
            raise ValueError('Error: Invalid recipient!')

        date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        message_length = len(message)
        file_count = len(files)

        to_email = Config.DEFAULT_RECIPIENT_EMAIL if recipient == 'legal' else recipient + Config.EMAIL_DOMAIN
        identifier = get_identifier(recipient)

        log_data = f"{date} - message to: {recipient}, identifier: {identifier}, length: {message_length}, file count: {file_count}"
        if reference:
            log_data += f", reference: {reference}"
        logging.info(log_data)

        message = create_email(to_email, identifier, message, files, reference)

        send_email(message)

        # If this is a legal submission with a Grant ID (reference), send to Kissflow
        if recipient == 'legal' and reference:
            kissflow_success = send_identifier_to_kissflow(reference, identifier)
            if kissflow_success:
                logging.info(f"Successfully sent identifier {identifier} to Kissflow for Grant ID {reference}")
            else:
                logging.warning(f"Failed to send identifier {identifier} to Kissflow for Grant ID {reference}")
                # Note: We don't fail the submission if Kissflow update fails
                # The email has already been sent successfully

        notice = f'Thank you! The relevant team was notified of your submission. Please record the identifier and refer to it in correspondence: {identifier}'

        return jsonify({'status': 'success', 'message': notice})

    except Exception as e:
        error_message = "An unexpected error occurred. Please try again later."
        logging.error(f"Internal error: {str(e)}")
        return jsonify({'status': 'failure', 'message': error_message})

@app.errorhandler(429)
def rate_limit_exceeded(e):
    """
    Handles requests that exceed the rate limit.
    """
    return jsonify({
        'status': 'failure',
        'message': 'Rate limit exceeded. You can only submit once per minute. Please try again later.'
    }), 429


@app.errorhandler(413)
def error413(e):
    return render_template('413.html'), 413

if __name__ == '__main__':
    app.run()
