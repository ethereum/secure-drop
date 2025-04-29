import os
import logging
from datetime import datetime
from random import Random
import requests
import base64

from flask import Flask, render_template, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Attachment, FileContent, FileName, FileType, Disposition

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
    valid_recipients = ['legal', 'devcon', 'esp', 'security', 'oleh']
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
    Creates an email message with attachments.
    """
    plain_text = text.replace('<br />', '\n')
    subject = f'Secure Form Submission {identifier}'
    if reference:
        subject = f'{reference} {subject}'
    
    message = Mail(
       from_email=FROMEMAIL,
       to_emails=to_email,
       subject=subject,
       plain_text_content=plain_text)

    for item in all_attachments:
        filename = item['filename']
        attachment = item['attachment']

        encoded_file = base64.b64encode(attachment.encode("utf-8")).decode()
        attachedFile = Attachment(
            FileContent(encoded_file),
            FileName(filename + '.pgp'),
            FileType('application/pgp-encrypted'),
            Disposition('attachment')
        )
        message.add_attachment(attachedFile)
    return message

def validate_recaptcha(recaptcha_response):
    """
    Validates the ReCaptcha response using Google's API.
    """
    secret_key = os.getenv('RECAPTCHASECRETKEY')
    payload = {
        'secret': secret_key,
        'response': recaptcha_response
    }
    response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=payload)
    result = response.json()

    # Log the validation result
    logging.info(f"ReCaptcha validation response: {result}")

    if not result.get('success'):
        raise ValueError('ReCaptcha verification failed.')

    # Check action and score thresholds for additional security
    if result.get('score', 1.0) < 0.5:
        raise ValueError('ReCaptcha score is too low, indicating potential abuse.')

def send_email(message):
    """
    Sends the email using SendGrid and logs detailed information for debugging.
    """
    try:
        sg = SendGridAPIClient(SENDGRIDAPIKEY)
        response = sg.send(message)
        logging.info('SendGrid response status code: %s', response.status_code)
        if response.status_code not in [200, 201, 202]:
            logging.error('SendGrid failed with status code: %s, response body: %s', response.status_code, response.body)
            raise ValueError(f"Error: Failed to send email. Status code: {response.status_code}, body: {response.body}")
    except Exception as e:
        logging.error('Error sending email via SendGrid: %s', str(e))
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

# Validate required environment variables
required_env_vars = ['RECAPTCHASITEKEY', 'RECAPTCHASECRETKEY', 'SENDGRIDAPIKEY', 'SENDGRIDFROMEMAIL']
validate_env_vars(required_env_vars)

RECAPTCHASITEKEY = os.environ['RECAPTCHASITEKEY']
RECAPTCHASECRETKEY = os.environ['RECAPTCHASECRETKEY']
SENDGRIDAPIKEY = os.environ['SENDGRIDAPIKEY']
FROMEMAIL = os.environ['SENDGRIDFROMEMAIL']

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
    return render_template('index.html', notice='', hascaptcha=True, attachments_number=Config.NUMBER_OF_ATTACHMENTS, recaptcha_sitekey=RECAPTCHASITEKEY)

@app.route('/submit-encrypted-data', methods=['POST'])
@limiter.limit("3 per minute")
def submit():
    try:
        # Parse JSON data from request
        data = request.get_json()

        # Validate ReCaptcha
        recaptcha_response = data.get('g-recaptcha-response', '')
        if not recaptcha_response:
            logging.warning(f"Missing ReCaptcha response. Potential bypass attempt detected from IP: {request.remote_addr}")
            return jsonify({'status': 'failure', 'message': 'Missing ReCaptcha token'}), 400

        try:
            validate_recaptcha(recaptcha_response)
        except ValueError as e:
            return jsonify({'status': 'failure', 'message': str(e)}), 400

        message = data['message']
        recipient = data['recipient']
        reference = data.get('reference', '')
        files = data['files']

        if not message:
            raise ValueError('Error: empty message!')

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

        notice = f'Thank you! The relevant team was notified of your submission. You could use the following identifier to refer to it in correspondence: <b>{identifier}</b>'

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
