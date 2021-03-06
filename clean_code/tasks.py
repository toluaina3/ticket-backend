from django.core.mail import send_mail, BadHeaderError
from django.contrib.auth import get_user_model
from django.utils.http import urlsafe_base64_encode
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.template.loader import render_to_string
from .celery import app
from request.models import bio
import logging
from datetime import datetime
from request.models import request_table, sla, user_request_table
from django.utils import timezone
from rest_framework_jwt.settings import api_settings
import requests

jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER


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


@app.task
def send_mail_password_reset_api(user):
    UserModel = get_user_model()
    user = UserModel.objects.get(pk=user)
    subject = "Ticket Password Reset Requested"
    email_template_name = "password/password_reset_email.txt"
    payload = jwt_payload_handler(user)
    token = jwt_encode_handler(payload)
    c = {
        "email": user.email,
        'domain': '127.0.0.1:8000',
        'site_name': 'Website',
        "uid": urlsafe_base64_encode(force_bytes(user.pk)),
        "user": user.get_full_name,
        'token': token,
        'protocol': 'http',
    }

    read = requests.get('http://127.0.0.1:8000/endpoints/password/update', headers={'Content-Type': 'application/json', 'Authorization': 'Bearer {}'.format(token)})

    print(read.status_code)
    email = read
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


@app.task
def send_mail_request_raised(user):
    UserModel = get_user_model()
    user = UserModel.objects.get(pk=user)
    subject = "Your Request Has Been Submitted"
    email = 'Your request has been acknowledged, a member of the IT team will be assigned soon'
    try:
        send_mail(subject, email, 'admin@tikcet.com', [user.email], fail_silently=False)
        logging.info('Email sent to {}'.format(user.get_full_name))
    except BadHeaderError:
        logging.warning('BadHeaderError when trying to send email to {}'.format(user.get_full_name))
    except ConnectionError:
        logging.warning(
            'No internet connection detected when trying to send email to {}'.format(user.get_full_name))


# the it support email has been hard coded into the function
@app.task
def send_mail_request_raised_it_team(user):
    UserModel = get_user_model()
    user = UserModel.objects.get(pk=user)
    email_id = 'itsupport@ticket.com'
    bio_user = bio.objects.get(bio_user_id=user.user_pk)
    subject = "A Request has been raised by {} {},  Department: {}, " \
              "Location: {}".format(user.first_name, user.last_name, bio_user.department, bio_user.branch)
    email = 'A request has been raised by {} {}, email:{}, ' \
            'kindly attend to it.'.format(user.first_name, user.last_name, user.email)
    try:
        send_mail(subject, email, 'admin@tikcet.com', [email_id], fail_silently=False)
        logging.info('Email sent to {}'.format(email_id))
    except BadHeaderError:
        logging.warning('BadHeaderError when trying to send email to {}'.format(email_id))
    except ConnectionError:
        logging.warning('No internet connection detected when trying to send email to {}'.format(email_id))


@app.task
def logging_info_task(msg):
    logging.info('{:%H:%M %d/%m/%Y }'.format(datetime.now()) + msg)


@app.task
def send_mail_task_assigned_user(user, assign):
    UserModel = get_user_model()
    user = UserModel.objects.get(pk=user)
    subject = "Your request has been assigned to an IT staff "
    email = (' Your request has been assigned to {}, he will be with your shortly. Thank you'.format(assign))
    try:
        send_mail(subject, email, 'admin@tikcet.com', [user.email], fail_silently=False)
        logging.info('Email sent to {}'.format(user.email))
    except BadHeaderError:
        logging.warning('BadHeaderError when trying to send email to {}'.format(user.get_full_name))
    except ConnectionError:
        logging.warning('No internet connection detected when trying to send email to {}'.format(user.get_full_name))


@app.task
def send_mail_task_assigned_started(user, assign):
    UserModel = get_user_model()
    user = UserModel.objects.get(pk=user)
    subject = "Your request has been assigned to an IT staff "
    email = ('Team rep {} is currently attending to your request. Thank you'.format(assign))
    try:
        send_mail(subject, email, 'admin@tikcet.com', [user.email], fail_silently=False)
        logging.info('Email sent to {}'.format(user.email))
    except BadHeaderError:
        logging.warning('BadHeaderError when trying to send email to {}'.format(user.get_full_name))
    except ConnectionError:
        logging.warning('No internet connection detected when trying to send email to {}'.format(user.get_full_name))


@app.task
def send_mail_task_response_requester(user, subject, email):
    UserModel = get_user_model()
    user = UserModel.objects.get(pk=user)
    subject = subject
    email = email
    try:
        send_mail(subject, email, 'admin@tikcet.com', [user.email], fail_silently=False)
        logging.info('Response Email sent to Requester {}'.format(user.email))
    except BadHeaderError:
        logging.warning('BadHeaderError when trying to send email to {}'.format(user.get_full_name))
    except ConnectionError:
        logging.warning('No internet connection detected when trying to send email to {}'.format(user.get_full_name))


@app.task
def send_mail_task_completed_user(user, assign):
    UserModel = get_user_model()
    user = UserModel.objects.get(pk=user)
    subject = "Your request has been completed "
    email = (' Your request has been completed by {}, kindly click the confirmed button on '
             'the platform to close out the request. Thank you'.format(assign))
    try:
        send_mail(subject, email, 'admin@tikcet.com', [user.email], fail_silently=False)
        logging.info('Email sent to {}'.format(user.email))
    except BadHeaderError:
        logging.warning('BadHeaderError when trying to send email to {}'.format(user.get_full_name))
    except ConnectionError:
        logging.warning('No internet connection detected when trying to send email to {}'.format(user.get_full_name))


@app.task
def send_mail_task_closed_user(user):
    UserModel = get_user_model()
    user = UserModel.objects.get(pk=user)
    subject = "Your request has been closed "
    email = ' Your request has been closed, Thank you'
    try:
        send_mail(subject, email, 'admin@tikcet.com', [user.email], fail_silently=False)
        logging.info('Email sent to {}'.format(user.email))
    except BadHeaderError:
        logging.warning('BadHeaderError when trying to send email to {}'.format(user.get_full_name))
    except ConnectionError:
        logging.warning('No internet connection detected when trying to send email to {}'.format(user.get_full_name))


@app.task
def send_mail_task_cancelled_request(user):
    UserModel = get_user_model()
    user = UserModel.objects.get(pk=user)
    subject = "Your request has been cancelled "
    email = ' Your request has been been cancelled, contact IT for more clarification. Thank you'
    try:
        send_mail(subject, email, 'admin@tikcet.com', [user.email], fail_silently=False)
        logging.info('Email sent to {} for request cancellation'.format(user.email))
    except BadHeaderError:
        logging.warning('BadHeaderError when trying to send email to {}'.format(user.get_full_name))
    except ConnectionError:
        logging.warning('No internet connection detected when trying to send email to {}'.format(user.get_full_name))


@app.task
def response_time_sla():
    try:
        query = user_request_table.objects.all()
        if query is not None:
            for lists in query:
                sla_time = user_request_table.objects.get \
                    (request_request_id=lists.request_request.pk).request_request.sla_category.sla_time
                if lists.request_request.request_open is not None \
                        or lists.request_request.close_request == 'Open':
                    response_time = lists.request_request.request_open + timezone.timedelta(minutes=sla_time)
                    # if lists.request_request.close_request =='Open':
                    if timezone.now() > response_time:
                        assign = lists.request_request.assigned_to
                        first = str(assign.split(' ')[0])
                        UserModel = get_user_model()
                        try:
                            user = UserModel.objects.get(first_name=first)
                            subject = "Pending request overdue "
                            email = ' A pending request assigned http://127.0.0.1:8000/request/assign/{} ' \
                                    'to you is overdue, ensure proper closure. ' \
                                    'Thank you'.format(lists.request_request.pk)
                            try:
                                send_mail(subject, email, 'admin@tikcet.com', [user.email], fail_silently=False)
                                logging.info('Overdue request Email sent to {}'.format(user.email))
                            except BadHeaderError:
                                logging.warning(
                                    'BadHeaderError when trying to send email to {}'.format(user.get_full_name))
                            except ConnectionError:
                                logging.warning(
                                    'No internet connection detected when trying to send email to {}'.format(
                                        user.get_full_name))
                        # condition if user do not exist
                        except UserModel.DoesNotExist:
                            pass
                # condition if timezone is None on the table
                else:
                    pass
    # condition if sla category is None
    except sla.DoesNotExist:
        pass
