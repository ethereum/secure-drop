import logging
from enum import Enum
from flask import request

ERROR_MESSAGES = {
    'email_failed': 'Failed to send email',
    'invalid_recipient': 'Invalid recipient',
    'turnstile_failed': 'Turnstile verification failed'
}

class SecurityEvent(Enum):
    TURNSTILE_FAILED = "turnstile_failed"
    EMAIL_SEND_FAILED = "email_send_failed"

def get_safe_error_message(error_key):
    return ERROR_MESSAGES.get(error_key, 'An error occurred')

def get_client_ip(request):
    if request.environ.get('HTTP_X_FORWARDED_FOR'):
        return request.environ['HTTP_X_FORWARDED_FOR'].split(',')[0]
    elif request.environ.get('HTTP_X_REAL_IP'):
        return request.environ.get('HTTP_X_REAL_IP')
    return request.environ.get('REMOTE_ADDR')

def log_security_event(event, details, request):
    logging.warning(f"Security event: {event.value} - Details: {details} - IP: {get_client_ip(request)}")

def sanitize_error_details(error):
    return {'error_type': type(error).__name__, 'error_message': str(error)}

def is_suspicious_error(error):
    suspicious_patterns = ['injection', 'exploit', 'malicious']
    error_str = str(error).lower()
    return any(pattern in error_str for pattern in suspicious_patterns)

def create_error_response(error_key, status_code=400):
    return {'status': 'failure', 'message': get_safe_error_message(error_key)}, status_code