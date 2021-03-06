from django.db import models
from verify.models import User
import uuid
from django.utils import timezone


# Create your models here.

# Create your models here.
class bio(models.Model):
    bio_id = models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True)
    bio_user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='bio_user_relation')
    job_title = models.CharField(max_length=40, blank=True, unique=False, default='Job Role')
    branch = models.CharField(max_length=20, blank=False, help_text='Location', default='Location')
    phone = models.CharField(max_length=12, blank=True, unique=True)
    department = models.CharField(max_length=25, blank=False, default='Department')

    class Meta:
        verbose_name_plural = 'Bio_table'

    def __str__(self):
        return '{} | {}'.format(self.job_title, self.bio_user.get_full_name())


class roles_table(models.Model):
    role_id = models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True)
    role_choices = (('User', 'User'), ('IT team', 'IT team'), ('Admin', 'Admin'))
    role = models.CharField(max_length=20, blank=False, default='User', choices=role_choices)

    class Meta:
        verbose_name_plural = 'roles_table'

    def __str__(self):
        return self.role


class permission(models.Model):
    permission_id = models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True)
    user_permit = models.ForeignKey(User, on_delete=models.CASCADE, related_name='permit_user')
    role_permit = models.ForeignKey(roles_table, on_delete=models.CASCADE, related_name='permit_user_role')

    class Meta:
        verbose_name_plural = 'permissions'

    def __str__(self):
        return str(self.user_permit)


class response_table(models.Model):
    response = models.TextField(max_length=1000, blank=False, help_text='Message to client', verbose_name='Message')
    time_response = models.DateTimeField(null=True)
    time_response_update = models.DateTimeField(null=True)


class AutoDateTimeField(models.DateTimeField):
    def pre_save(self, model_instance, add):
        return timezone.now()


class priority_tables(models.Model):
    priority_pk = models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True)
    priority_choice = (('Low', 'Low'), ('Medium', 'Medium'), ('High', 'High'))
    priority_field = models.CharField(max_length=10, default='Low', choices=priority_choice, blank=False)


class sla(models.Model):
    id = models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True)
    sla_category = models.CharField(max_length=30, blank=False, unique=True)
    sla_time = models.IntegerField(blank=False)
    sla_priority = models.ForeignKey(priority_tables, on_delete=models.CASCADE, related_name='sla_priority_table_link')

    # sla_status = models.CharField(max_length=10, blank=False, default=True)

    class Meta:
        verbose_name_plural = 'SLA'

    def __str__(self):
        return self.sla_category


class request_table(models.Model):
    id = models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True)
    request = models.TextField(max_length=2000, blank=False, help_text='What is your request?', verbose_name='Subject')
    # create task to send email to IT team
    request_open = models.DateTimeField(null=True)
    request_time_update = models.DateTimeField(null=True)
    request_time_started = models.DateTimeField(null=True)
    request_time_closed = models.DateTimeField(null=True)
    # not included in the form, auto fills
    # create task to send email to user for assigned request
    assigned_to = models.CharField(max_length=40, blank=True, default='None')
    copy_team = models.CharField(max_length=40, blank=True, help_text='Copy team members')
    # view only to IT team
    close = (('Cancelled', 'Cancelled'), ('Open', 'Open'), ('Completed', 'Completed'),
             ('Started', 'Started'), ('Closed', 'Closed'))
    confirm = models.BooleanField(default=False)
    close_request = models.CharField(max_length=15, blank=True, choices=close, default='Open')
    ticket_number = models.CharField(max_length=13, blank=True)
    sla_category = models.ForeignKey(sla, on_delete=models.CASCADE, related_name='request_sla_request')

    class Meta:
        verbose_name_plural = 'Request_table'

    # update the time when the request in close, can be done in view too
    def time_to_close_request(self):
        if self.close_request == 'Open':
            self.request_open = timezone.now()
            return self.request_open

    def save(self, *args, **kwargs):
        self.time_to_close_request()
        super(request_table, self).save(*args, **kwargs)

    def __str__(self):
        return self.request


class ticket_message_table(models.Model):
    ticket_uuid_message = models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True)
    ticket_message = models.ForeignKey(response_table, on_delete=models.CASCADE,
                                       related_name='ticket_response_relation')
    ticket_request = models.ForeignKey(request_table, on_delete=models.CASCADE, related_name='ticket_request_relation')


# many to many relation for users to make multiple requests
class user_request_table(models.Model):
    id = models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True)
    user_request = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_request_link')
    request_request = models.ForeignKey(request_table, on_delete=models.CASCADE, related_name='request_request_link')

    class Meta:
        verbose_name_plural = 'User_request_table'

    def __str__(self):
        return '{} | {}'.format(self.user_request.get_full_name, self.request_request.request)


class custom_email_message(models.Model):
    id = models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True)
    assign_email = models.TextField \
        (max_length=2000, blank=True, verbose_name='Type your request assign email to Customers')
    complete_email = models.TextField \
        (max_length=2000, blank=True, verbose_name='Type your request complete email to Customers')
    closed_request_email = models.TextField \
        (max_length=2000, blank=True, verbose_name='Type your request closed email to Customers')
    cancelled_request_email = models.TextField \
        (max_length=2000, blank=True, verbose_name='Type your request cancelled email to Customers')
