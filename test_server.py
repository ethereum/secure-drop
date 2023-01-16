from datetime import datetime
import server

assert server.valid_recipient('legal')
assert not server.valid_recipient('nonlegal')

assert 'devcon:2023:01:01:12:00:00:123' == server.get_identifier('devcon', datetime(2023, 1, 1, 12), 123)


toEmail = 'someone@somewhere.org'
identifier = 'just:some:identifier'
text = 'encrypted_blablabla'
filename = 'myfile.txt'
attachment = 'encrypted_file_content'

email = server.create_email(toEmail, identifier, text, filename, attachment)

assert server.FROMEMAIL == email.from_email.email
assert toEmail == email.personalizations[0].tos[0]['email']
assert "Secure Form Submission just:some:identifier" == email.subject.subject
assert text == email.contents[0].content
assert 1 == len(email.attachments)

a = email.attachments[0]
assert "myfile.txt.pgp" == a.file_name.file_name
assert "application/pgp-encrypted" == a.file_type.file_type
assert "ZW5jcnlwdGVkX2ZpbGVfY29udGVudA==" == a.file_content.file_content

