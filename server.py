import os
import logging
from datetime import datetime
from random import Random
import base64

from flask import Flask, render_template, request, jsonify
from flask_recaptcha import ReCaptcha

from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import (Mail, Attachment, FileContent, FileName, FileType, Disposition)

from dotenv import load_dotenv

load_dotenv()

if not set(['RECAPTCHASITEKEY', 'RECAPTCHASECRETKEY', 'SENDGRIDAPIKEY', 'SENDGRIDFROMEMAIL']).issubset(os.environ):
    print("Failed to start. Please set the environment variables RECAPTCHASITEKEY, RECAPTCHASECRETKEY, SENDGRIDAPIKEY, and SENDGRIDFROMEMAIL")
    exit(1)

RECAPTCHASITEKEY = os.environ['RECAPTCHASITEKEY']
RECAPTCHASECRETKEY = os.environ['RECAPTCHASECRETKEY']
SENDGRIDAPIKEY = os.environ['SENDGRIDAPIKEY']
FROMEMAIL = os.environ['SENDGRIDFROMEMAIL']

# this needs to be reflected in the `templates/index.html` file
NUMBER_OF_ATTACHMENTS = int(os.environ.get('NUMBEROFATTACHMENTS', '10'))
DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'

app = Flask(__name__)
app.config['RECAPTCHA_SITE_KEY'] = RECAPTCHASITEKEY
app.config['RECAPTCHA_SECRET_KEY'] = RECAPTCHASECRETKEY
app.config['MAX_CONTENT_LENGTH'] = 15 * 1024 * 1024    # 15 Mb limit
recaptcha = ReCaptcha(app)

app.config['LOG_FILE'] = 'secure-drop.log'
logging.basicConfig(filename=app.config['LOG_FILE'], level=logging.INFO)

def parse_form(form):
    text = form['message']
    recipient = form['recipient']

    all_attachments = []
    for i in range(NUMBER_OF_ATTACHMENTS):
        attachment = form['attachment-%s' % i]
        filename = form['filename-%s' % i].encode('ascii', 'ignore').decode() # remove non-ascii characters
        if not attachment:
            continue
        all_attachments.append((filename, attachment))
    return text, recipient, all_attachments

def valid_recipient(recipient):
    if recipient in ['legal', 'devcon', 'esp', 'security', 'oleh']:
        return True
    return False

def get_identifier(recipient, now=None, randint=None):
    if now is None:
        now = datetime.now()
    if randint is None:
        randint = Random().randint(1000, 9999)
    return '%s:%s:%s' % (recipient, now.strftime('%Y:%m:%d:%H:%M:%S'), randint)

def create_email(toEmail, identifier, text, all_attachments):
    message = Mail(
       from_email=FROMEMAIL,
       to_emails=toEmail,
       subject='Secure Form Submission %s' % identifier,
       html_content=text)

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

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html', notice='', hascaptcha=not DEBUG, attachments_number=NUMBER_OF_ATTACHMENTS, recaptcha_sitekey=RECAPTCHASITEKEY)

@app.route('/submit-encrypted-data', methods=['POST'])
def submit():
    try:
        # Parse JSON data from request
        data = request.get_json()

        # Won't even look on Captcha for debug mode
        if not DEBUG:
            if not recaptcha.verify(response=data['g-recaptcha-response']):
                raise ValueError('Error: ReCaptcha verification failed! You would need to re-submit the request.')
        
        # Extract fields from JSON data
        message = data['message']
        recipient = data['recipient']
        files = data['files']

        if not message:
            raise ValueError('Error: empty message!')

        if not valid_recipient(recipient):
            raise ValueError('Error: Invalid recipient!')
        
        # Get submission statistics
        date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        message_length = len(message)
        file_count = len(files)
        
        toEmail = "kyc@ethereum.org" if recipient == 'legal' else recipient + "@ethereum.org"
        identifier = get_identifier(recipient)

        log_data = f"{date} - message to: {recipient}, identifier: {identifier}, length: {message_length}, file count: {file_count}"
        logging.info(log_data)

        message = create_email(toEmail, identifier, message, files)

        if DEBUG:
            print("Attempt to send email to %s" % toEmail)
            print(message.get())
        else:
            sg = SendGridAPIClient(SENDGRIDAPIKEY)
            response = sg.send(message)
            if not response.status_code in [200, 201, 202]:
                logging.error("Failed to send email: %s" % response.body)
                logging.error("Headers: %s" % response.headers)
                raise ValueError('Error: Failed to send email. Please try again later. Code: %s' % response.status_code)

        notice = 'Thank you! The relevant team was notified of your submission. You could use a following identifier to refer to it in correspondence: <b>' + identifier + '</b>'
        
        # Return success response
        return jsonify({'status': 'success', 'message': notice})
    
    except Exception as e:
        # Log error message and return failure response
        error_message = str(e)
        print(error_message)
        return jsonify({'status': 'failure', 'message': error_message})


@app.errorhandler(413)
def error413(e):
    return render_template('413.html'), 413

if __name__ == '__main__':
    app.run()
