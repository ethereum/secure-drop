from os import environ
from unittest.mock import patch

environ.setdefault("TURNSTILE_SITE_KEY", "test-site-key")
environ.setdefault("TURNSTILE_SECRET_KEY", "test-secret-key")
environ.setdefault("AWS_ACCESS_KEY_ID", "test")
environ.setdefault("AWS_SECRET_ACCESS_KEY", "test")
environ.setdefault("AWS_REGION", "us-east-1")
environ.setdefault("SES_FROM_EMAIL", "secure-drop@example.org")
environ.setdefault("NUMBEROFATTACHMENTS", "2")
environ.setdefault("VERIFIER_URL", "http://verifier:3000/")

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

class FakeVerifierResponse:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self._body = body

    def json(self):
        if self._body is None:
            raise ValueError("No JSON object could be decoded")
        return self._body


def submit(payload, turnstile_ok=True, verifier=None):
    """Posts to the endpoint with Turnstile, SES, Kissflow and the verifier sidecar patched out.
    `verifier` is a FakeVerifierResponse, an exception to raise, or None when the sidecar must not be called."""
    def turnstile(token):
        if not turnstile_ok:
            raise ValueError("Turnstile verification failed.")

    def post(url, json, timeout):
        assert url == "http://verifier:3000/verify"
        assert json["identifier"].startswith("legal:") and json["reference"] == payload.get("reference")
        if isinstance(verifier, Exception):
            raise verifier
        return verifier

    with patch.object(server, "validate_turnstile", side_effect=turnstile), \
         patch.object(server, "send_email") as send_email, \
         patch.object(server, "send_identifier_to_kissflow", return_value=True) as kissflow, \
         patch.object(server.requests, "post", side_effect=post) as sidecar:
        response = client.post("/submit-encrypted-data", json=payload)
    if verifier is None:
        assert not sidecar.called
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
assert not sent["Subject"].endswith("[ZK-VERIFIED]")
body, attachment = sent.get_payload()
assert body.get_payload().endswith("-----END PGP MESSAGE-----\n\nPassport verification: not attempted.")
assert attachment.get_filename() == "passport.jpg.pgp"
assert kissflow.call_args.args == ("FY26-1234", response.json["message"].rsplit(" ", 1)[1], None)

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


# --- passport verification -----------------------------------------------

proof = {"proofs": [{"proof": "ab", "name": "disclose_bytes", "version": "1.0.0"}], "queryResult": {"fullname": {"disclose": {"result": "JANE"}}}}
verified = FakeVerifierResponse(200, {
    "verified": True,
    "fieldsBlockArmored": "-----BEGIN PGP MESSAGE-----\nfields\n-----END PGP MESSAGE-----",
    "bundleArmored": "-----BEGIN PGP MESSAGE-----\nbundle\n-----END PGP MESSAGE-----",
})

response, send_email, kissflow = submit({**base, "passport": proof}, verifier=verified)
assert response.status_code == 200
sent = send_email.call_args.args[0]
assert sent["Subject"].endswith("[ZK-VERIFIED]")
body, file_part, bundle_part = sent.get_payload()
assert body.get_payload() == (
    "-----BEGIN PGP MESSAGE-----\n...\n-----END PGP MESSAGE-----"
    "\n\n-----BEGIN PGP MESSAGE-----\nfields\n-----END PGP MESSAGE-----"
    "\n\n" + server.PASSPORT_STATUS["verified"]
)
assert file_part.get_filename() == "passport.jpg.pgp"
assert bundle_part.get_filename() == "passport-proof-bundle.json.pgp"
assert bundle_part.get_payload(decode=True) == b"-----BEGIN PGP MESSAGE-----\nbundle\n-----END PGP MESSAGE-----"
assert kissflow.call_args.args[2] == "zk-verified"

response, send_email, _ = submit({**base, "passport": proof}, verifier=FakeVerifierResponse(200, {"verified": False}))
assert response.status_code == 400
assert response.json["code"] == "proof_verification_failed"
assert not send_email.called

for down in (
    FakeVerifierResponse(503, {"error": "busy"}),
    FakeVerifierResponse(503, {"error": "verification_unavailable"}),
    FakeVerifierResponse(500, {"error": "verification_error"}),
    FakeVerifierResponse(200, None),  # not JSON
    FakeVerifierResponse(200, {"verified": True}),  # missing the encrypted blocks
    server.requests.ConnectionError(),
):
    response, send_email, _ = submit({**base, "passport": proof}, verifier=down)
    assert response.status_code == 502, down
    assert response.json["code"] == "verification_unavailable"
    assert not send_email.called

# A request the verifier itself refuses, or a proof field that is not an object, is a bad proof, not an outage.
response, send_email, _ = submit({**base, "passport": proof}, verifier=FakeVerifierResponse(400, {"error": "bad_request"}))
assert response.status_code == 400 and response.json["code"] == "proof_verification_failed"
response, send_email, _ = submit({**base, "passport": "yes"})
assert response.status_code == 400 and response.json["code"] == "proof_verification_failed"
assert not send_email.called

for status in ("failed", "unavailable"):
    response, send_email, kissflow = submit({**base, "passportStatus": status})
    assert response.status_code == 200
    sent = send_email.call_args.args[0]
    assert not sent["Subject"].endswith("[ZK-VERIFIED]")
    assert sent.get_payload()[0].get_payload().endswith(server.PASSPORT_STATUS[status])
    assert kissflow.call_args.args[2] is None

response, send_email, kissflow = submit({**base, "passportStatus": "bogus"})
assert send_email.call_args.args[0].get_payload()[0].get_payload().endswith(server.PASSPORT_STATUS["not-attempted"])

response, send_email, kissflow = submit({**base, "recipient": "devcon", "passport": proof})
assert response.status_code == 200
assert "Passport verification" not in send_email.call_args.args[0].get_payload()[0].get_payload()
assert not kissflow.called

print("all tests passed")
