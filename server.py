import os
import logging
from datetime import datetime
from random import Random
import requests
import base64
import json
import uuid

from flask import Flask, render_template, request, jsonify, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

import boto3
from botocore.exceptions import ClientError

from dotenv import load_dotenv

from error_handling import (
    ERROR_MESSAGES,
    SecurityEvent,
    get_safe_error_message,
    get_client_ip,
    log_security_event,
    sanitize_error_details,
    is_suspicious_error,
    create_error_response
)
from logging_config import setup_logging

load_dotenv()

class Config:
    MAX_CONTENT_LENGTH = 15 * 1024 * 1024  # 15 MB
    EMAIL_DOMAIN = "@ethereum.org"
    DEFAULT_RECIPIENT_EMAIL = "george.cordalis@ethereum.org"
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

    # Log the validation result (without sensitive data)
    app_logger.info(f"Turnstile validation response success: {result.get('success')}")

    if not result.get('success'):
        error_codes = result.get('error-codes', [])
        app_logger.error(f"Turnstile verification failed with error codes: {error_codes}")
        
        # Log security event
        log_security_event(
            SecurityEvent.TURNSTILE_FAILED,
            {'error_codes': error_codes},
            request
        )
        
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
        app_logger.info('AWS SES email sent successfully. MessageId: %s', message_id)
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        sanitized_details = sanitize_error_details(e)
        app_logger.error('AWS SES error: Code=%s', error_code, extra=sanitized_details)
        
        # Log security event for email failures
        log_security_event(
            SecurityEvent.EMAIL_SEND_FAILED,
            {'aws_error_code': error_code},
            request
        )
        
        # Raise with generic error message
        raise ValueError('email_failed')
            
    except Exception as e:
        app_logger.error('Error sending email via AWS SES', extra=sanitize_error_details(e))
        raise ValueError('email_failed')


def get_forwarded_address():
    # Use the get_client_ip function from error_handling module
    return get_client_ip(request) or get_remote_address()

def find_aog_item_by_grant_id(grant_id):
    """
    Finds an AOG (Approval of Grants) item in Kissflow by Grant ID.
    Uses the admin endpoint to get all items and searches through them.
    Returns the item ID if found, None otherwise.
    """
    try:
        subdomain = os.getenv('KISSFLOW_SUBDOMAIN', 'ethereum')
        access_key_id = os.getenv('KISSFLOW_ACCESS_KEY_ID')
        access_key_secret = os.getenv('KISSFLOW_ACCESS_KEY_SECRET')
        account_id = os.getenv('KISSFLOW_ACCOUNT_ID')
        process_id = os.getenv('KISSFLOW_PROCESS_ID')
        
        if not all([access_key_id, access_key_secret, account_id, process_id]):
            logging.error("Missing Kissflow configuration")
            return None
        
        headers = {
            'Accept': 'application/json',
            'X-Access-Key-Id': access_key_id,
            'X-Access-Key-Secret': access_key_secret
        }
        
        # Use admin endpoint to get all items
        page_number = 1
        page_size = 100  # Get 100 items per page
        
        while True:
            # Kissflow admin API endpoint to get all items
            url = f"https://{subdomain}.kissflow.com/process/2/{account_id}/admin/{process_id}/item"
            
            params = {
                'page_number': page_number,
                'page_size': page_size,
                'apply_preference': False
            }
            
            response = requests.get(url, headers=headers, params=params)
            
            if response.status_code != 200:
                logging.error(f"Kissflow API error: {response.status_code} - {response.text}")
                return None
            
            data = response.json()
            
            # The response structure contains table data with items
            # Look for items in the response structure
            items_found = []
            
            # Check if there's a table structure in the response
            for key, val in data.items():
                if key != "Data": 
                    continue
                    
                if isinstance(val, list):
                    for page_data in val:
                        if isinstance(page_data, dict) and '_created_by' in page_data:
                            items_found.append(page_data)
           
            #print(items_found)
            # Search through the items for matching Grant ID
            for item in items_found:
                # Check various possible field names for the Grant ID
                grant_id_fields = ['Request_number', 'GrantId', 'Grant_ID', 'grant_id', 'PONumber']
                
                for field in grant_id_fields:
                    if field in item and str(item[field]) == str(grant_id):
                        logging.info(f"Found AOG item with ID {item.get('_id')} for Grant ID {grant_id}")
                        return item.get('_id')
            
            # If we found fewer items than page_size, we've reached the end
            if len(items_found) < page_size:
                break
                
            page_number += 1
            
            # Safety check to prevent infinite loops
            if page_number > 100:  # Max 10,000 items (100 pages * 100 items)
                logging.warning("Reached maximum page limit while searching for Grant ID")
                break
        
        logging.warning(f"No AOG item found for Grant ID: {grant_id}")
        return None
            
    except Exception as e:
        logging.error(f"Error finding AOG item: {str(e)}")
    
    return None

def update_aog_kyc_comments(item_id, legal_identifier):
    """
    Updates the KYC_Comments field in a Kissflow AOG item with the legal identifier.
    Uses the admin PUT endpoint to update item details.
    """
    try:
        subdomain = os.getenv('KISSFLOW_SUBDOMAIN', 'ethereum')
        access_key_id = os.getenv('KISSFLOW_ACCESS_KEY_ID')
        access_key_secret = os.getenv('KISSFLOW_ACCESS_KEY_SECRET')
        account_id = os.getenv('KISSFLOW_ACCOUNT_ID')
        process_id = os.getenv('KISSFLOW_PROCESS_ID')
        
        if not all([access_key_id, access_key_secret, account_id, process_id]):
            logging.error("Missing Kissflow configuration")
            return False
        
        # First, get the current item details to preserve existing data
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'X-Access-Key-Id': access_key_id,
            'X-Access-Key-Secret': access_key_secret
        }
        
        # Get current item details using admin endpoint
        get_url = f"https://{subdomain}.kissflow.com/process/2/{account_id}/admin/{process_id}/{item_id}"
        get_response = requests.get(get_url, headers=headers)
        
        if get_response.status_code != 200:
            logging.error(f"Failed to get current item details: {get_response.status_code} - {get_response.text}")
            return False
        
        current_item = get_response.json()
        
        # Update the KYC_Comments field while preserving other fields
        current_item['KYC_Comments'] = legal_identifier
        
        # Remove all fields starting with '_' before sending to Kissflow
        filtered_item = {k: v for k, v in current_item.items() if not k.startswith('_')}
        
        # Use admin PUT endpoint to update the item
        put_url = f"https://{subdomain}.kissflow.com/process/2/{account_id}/admin/{process_id}/{item_id}"
        
        response = requests.put(put_url, headers=headers, json=filtered_item)
        
        if response.status_code == 200:
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
limiter = Limiter(
    get_forwarded_address, 
    app=app, 
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"  # Explicitly use memory storage to suppress warning
)

# Configure structured logging
app_logger, security_logger, perf_logger = setup_logging()

# Keep compatibility with old logging configuration
log_file = os.environ.get('LOG_FILE', '')
if log_file:
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.INFO)
    app_logger.addHandler(file_handler)

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
