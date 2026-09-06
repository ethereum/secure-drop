from os import environ
from unittest.mock import patch

environ.setdefault("TURNSTILE_SITE_KEY", "test-site-key")
environ.setdefault("TURNSTILE_SECRET_KEY", "test-secret-key")
environ.setdefault("AWS_ACCESS_KEY_ID", "test")
environ.setdefault("AWS_SECRET_ACCESS_KEY", "test")
environ.setdefault("AWS_REGION", "us-east-1")
environ.setdefault("SES_FROM_EMAIL", "secure-drop@example.org")
environ.setdefault("NUMBEROFATTACHMENTS", "2")

from datetime import datetime
import server

server.limiter.enabled = False
client = server.app.test_client()


# --- helpers -------------------------------------------------------------

form = {
    "message": "hello",
    "recipient": "legal",
    "reference": "FY26-1234",
    "filename-0": "file0.txt",
    "attachment-0": "content0",
    "filename-1": "file1.txt",
    "attachment-1": "content1",
}
text, recipient, reference, all_attachments = server.parse_form(form)
assert text == "hello"
assert recipient == "legal"
assert reference == "FY26-1234"
assert all_attachments == [("file0.txt", "content0"), ("file1.txt", "content1")]

form["attachment-1"] = ""
assert server.parse_form(form)[3] == [("file0.txt", "content0")]

assert server.sanitize_filename("../../etc/passwd") == "etcpasswd"

assert server.valid_recipient("legal")
assert not server.valid_recipient("nonlegal")

assert server.get_identifier("devcon", datetime(2023, 1, 1, 12), 123) == "devcon:2023:01:01:12:00:00:123"


# --- email ---------------------------------------------------------------

files = [{"filename": "myfile.txt", "attachment": "encrypted_file_content"}]
email = server.create_email("someone@somewhere.org", "just:some:identifier", "line1<br />line2", files, "FY26-1234")

assert email["From"] == server.FROMEMAIL
assert email["To"] == "someone@somewhere.org"
assert email["Subject"] == "FY26-1234 Secure Form Submission just:some:identifier"

body, attachment = email.get_payload()
assert body.get_payload() == "line1\nline2"
assert attachment.get_filename() == "myfile.txt.pgp"
assert attachment.get_payload(decode=True) == b"encrypted_file_content"

email = server.create_email("someone@somewhere.org", "just:some:identifier", "hi", [])
assert email["Subject"] == "Secure Form Submission just:some:identifier"
assert len(email.get_payload()) == 1


# --- submit endpoint -----------------------------------------------------

def submit(payload, turnstile_ok=True):
    def turnstile(token):
        if not turnstile_ok:
            raise ValueError("Turnstile verification failed.")

    with patch.object(server, "validate_turnstile", side_effect=turnstile), \
         patch.object(server, "send_email") as send_email, \
         patch.object(server, "send_identifier_to_kissflow", return_value=True) as kissflow:
        response = client.post("/submit-encrypted-data", json=payload)
    return response, send_email, kissflow


base = {
    "cf-turnstile-response": "token",
    "recipient": "legal",
    "reference": "FY26-1234",
    "message": "-----BEGIN PGP MESSAGE-----<br />...<br />-----END PGP MESSAGE-----",
    "files": [{"filename": "passport.jpg", "attachment": "-----BEGIN PGP MESSAGE-----\n...\n-----END PGP MESSAGE-----"}],
}

response, send_email, kissflow = submit(base)
assert response.status_code == 200
assert response.json["status"] == "success"
assert "legal:" in response.json["message"]
sent = send_email.call_args.args[0]
assert sent["To"] == server.Config.DEFAULT_RECIPIENT_EMAIL
assert sent["Subject"].startswith("FY26-1234 Secure Form Submission legal:")
assert sent.get_payload()[1].get_filename() == "passport.jpg.pgp"
assert kissflow.call_args.args[0] == "FY26-1234"

response, send_email, kissflow = submit({**base, "recipient": "devcon"})
assert response.status_code == 200
assert send_email.call_args.args[0]["To"] == "devcon@ethereum.org"
assert not kissflow.called

response, send_email, _ = submit({**base, "cf-turnstile-response": ""})
assert response.status_code == 400
assert not send_email.called

response, send_email, _ = submit(base, turnstile_ok=False)
assert response.status_code == 400
assert not send_email.called

response, send_email, _ = submit({**base, "recipient": "nobody"})
assert response.json["status"] == "failure"
assert not send_email.called

print("all tests passed")
