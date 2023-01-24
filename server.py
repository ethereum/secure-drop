import os
from datetime import datetime
from random import Random
import base64

from flask import Flask, render_template, request
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

app = Flask(__name__)
app.config['RECAPTCHA_SITE_KEY'] = RECAPTCHASITEKEY
app.config['RECAPTCHA_SECRET_KEY'] = RECAPTCHASECRETKEY
app.config['MAX_CONTENT_LENGTH'] = 15 * 1024 * 1024    # 15 Mb limit
recaptcha = ReCaptcha(app)


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
    if recipient in ['legal', 'devcon', 'esp', 'security']:
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

    for filename, attachment in all_attachments:
        encoded_file = base64.b64encode(attachment.encode("utf-8")).decode()
        attachedFile = Attachment(
            FileContent(encoded_file),
            FileName(filename + '.pgp'),
            FileType('application/pgp-encrypted'),
            Disposition('attachment')
        )
        message.add_attachment(attachedFile)
    return message

@app.route('/', methods=['GET', 'POST'])
def index():
    notice = ''
    if request.method == 'POST':
        if recaptcha.verify():
            text, recipient, all_attachments = parse_form(request.form)

            if not valid_recipient(recipient):
                notice = 'Error: Invalid recipient!'
                return render_template('result.html', notice=notice)

            toEmail = "kyc@ethereum.org" if recipient == 'legal' else recipient + "@ethereum.org"
            identifier = get_identifier(recipient)

            message = create_email(toEmail, identifier, text, all_attachments)

            try:
                sg = SendGridAPIClient(SENDGRIDAPIKEY)
                response = sg.send(message)
            except Exception as e:
                print(e.message)
            notice = 'Thank you! The relevant team was notified of your submission. You could use a following identifier to refer to it in correspondence: ' + identifier
            return render_template('result.html', notice=notice)
        else:
            notice = 'Please fill out the ReCaptcha!'
    return render_template('index.html', notice=notice, attachments_number=NUMBER_OF_ATTACHMENTS)

@app.errorhandler(413)
def error413(e):
    return render_template('413.html'), 413

if __name__ == '__main__':
    app.run()
