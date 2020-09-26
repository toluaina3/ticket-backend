from django.core.mail import send_mail, BadHeaderError
from django.contrib.auth import get_user_model
from django.utils.http import urlsafe_base64_encode
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.template.loader import render_to_string
from .celery import app
import logging


@app.task
def send_mail_password_reset(user):
    UserModel = get_user_model()
    user = UserModel.objects.get(pk=user)
    subject = "Ticket Password Reset Requested"
    email_template_name = "password/password_reset_email.txt"
    c = {
        "email": user.email,
        'domain': '127.0.0.1:8000',
        'site_name': 'Website',
        "uid": urlsafe_base64_encode(force_bytes(user.pk)),
        "user": user.get_full_name,
        'token': default_token_generator.make_token(user),
        'protocol': 'http',
    }
    email = render_to_string(email_template_name, c)
    # super admin can not reset password by email
    # cache query for superuser
    try:
        send_mail(subject, email, 'admin@tikcet.com', [user.email], fail_silently=False)
        logging.info('Email sent to {}'.format(user.get_full_name))
    except BadHeaderError:
        logging.warning('BadHeaderError when trying to send email to {}'.format_map(user.get_full_name))
    except ConnectionError:
        logging.warning(
            'No internet connection detected when trying to send email to {}'.format_map(user.get_full_name))
