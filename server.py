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

app = Flask(__name__)
app.config['RECAPTCHA_SITE_KEY'] = RECAPTCHASITEKEY
app.config['RECAPTCHA_SECRET_KEY'] = RECAPTCHASECRETKEY
app.config['MAX_CONTENT_LENGTH'] = 15 * 1024 * 1024    # 15 Mb limit
recaptcha = ReCaptcha(app)


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

def create_email(toEmail, identifier, text, filename, attachment):
    message = Mail(
       from_email=FROMEMAIL,
       to_emails=toEmail,
       subject='Secure Form Submission %s' % identifier,
       html_content=text)

    if attachment:
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
            text = request.form['message']
            attachment = request.form['attachment']
            recipient = request.form['recipient']
            filename = request.form['filename'].encode('ascii', 'ignore').decode() # remove non-ascii characters
            
            if not valid_recipient(recipient):
                notice = 'Error: Invalid recipient!'
                return render_template('result.html', notice=notice)

            toEmail = "kyc@ethereum.org" if recipient == 'legal' else recipient + "@ethereum.org"
            identifier = get_identifier(recipient)

            message = create_email(toEmail, identifier, text, filename, attachment)

            try:
               sg = SendGridAPIClient(SENDGRIDAPIKEY)
               response = sg.send(message)
            except Exception as e:
               print(e.message)
            notice = 'Thank you! The relevant team was notified of your submission. You could use a following identifier to refer to it in correspondence: ' + identifier
            return render_template('result.html', notice=notice)
        else:
            notice = 'Please fill out the ReCaptcha!'
    return render_template('index.html', notice=notice)

@app.errorhandler(413)
def error413(e):
    return render_template('413.html'), 413

if __name__ == '__main__':
    app.run()
