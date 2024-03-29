from os import environ

environ.setdefault("SENDGRIDFROMEMAIL", "person@sender.org")
environ.setdefault("SENDGRIDAPIKEY", "testsendgridapikey")
environ.setdefault("RECAPTCHASITEKEY", "testrecaptchasitekey")
environ.setdefault("RECAPTCHASECRETKEY", "testrecaptchasecretkey")
environ.setdefault("NUMBEROFATTACHMENTS", "2")

from datetime import datetime
import server

form = {
    'message': 'hello',
    'recipient': 'a@a.a',

    'filename-0': 'file0.txt',
    'attachment-0': 'content0',
    'filename-1': 'file1.txt',
    'attachment-1': 'content1',
}
text, recipient, all_attachments = server.parse_form(form)
assert 'hello' == text
assert 'a@a.a' == recipient
assert [
    ('file0.txt', 'content0'),
    ('file1.txt', 'content1'),
] == all_attachments

# empty attachment fields are omitted
form['attachment-1'] = ''
text, recipient, all_attachments = server.parse_form(form)
assert [
    ('file0.txt', 'content0'),
] == all_attachments


assert server.valid_recipient('legal')
assert not server.valid_recipient('nonlegal')

assert 'devcon:2023:01:01:12:00:00:123' == server.get_identifier('devcon', datetime(2023, 1, 1, 12), 123)

toEmail = 'someone@somewhere.org'
identifier = 'just:some:identifier'
text = 'encrypted_blablabla'
all_attachments = [
    ('myfile.txt', 'encrypted_file_content'),
]

email = server.create_email(toEmail, identifier, text, all_attachments)

assert server.FROMEMAIL == email.from_email.email
assert toEmail == email.personalizations[0].tos[0]['email']
assert "Secure Form Submission just:some:identifier" == email.subject.subject
assert text == email.contents[0].content
assert 1 == len(email.attachments)

a = email.attachments[0]
assert "myfile.txt.pgp" == a.file_name.file_name
assert "application/pgp-encrypted" == a.file_type.file_type
assert "ZW5jcnlwdGVkX2ZpbGVfY29udGVudA==" == a.file_content.file_content

two_attachments = [
    ('myfile1.txt', 'encrypted_file_content1'),
    ('myfile2.txt', 'encrypted_file_content2'),
]

email = server.create_email(toEmail, identifier, text, two_attachments)

a0 = email.attachments[0]
assert "myfile2.txt.pgp" == a0.file_name.file_name
assert "application/pgp-encrypted" == a0.file_type.file_type
assert "ZW5jcnlwdGVkX2ZpbGVfY29udGVudDI=" == a0.file_content.file_content

a1 = email.attachments[1]
assert "myfile1.txt.pgp" == a1.file_name.file_name
assert "application/pgp-encrypted" == a1.file_type.file_type
assert "ZW5jcnlwdGVkX2ZpbGVfY29udGVudDE=" == a1.file_content.file_content

