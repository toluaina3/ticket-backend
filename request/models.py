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
    response = models.TextField(max_length=1000, blank=False, help_text='response to request')
    first_response = models.DateTimeField(auto_now_add=True)
    later_response = models.DateTimeField(auto_now=True)


class AutoDateTimeField(models.DateTimeField):
    def pre_save(self, model_instance, add):
        return timezone.now()


class sla(models.Model):
    #sla_pk = models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True)
    sla_category = models.CharField(max_length=30, blank=False, unique=True)
    sla_time = models.IntegerField(blank=False)
    #sla_status = models.CharField(max_length=10, blank=False, default=True)

    class Meta:
        verbose_name_plural = 'SLA'

    def __str__(self):
        return self.sla_category


class request_table(models.Model):
    request = models.TextField(max_length=2000, blank=False, help_text='What is your request')
    # create task to send email to IT team
    request_open = models.DateTimeField(null=True)
    request_time_closed = models.DateTimeField(null=True)
    # not included in the form, auto fills
    # create task to send email to user for assigned request
    assigned_to = models.CharField(max_length=40, blank=True, default='None')
    copy_team = models.CharField(max_length=40, blank=True, help_text='Copy team members')
    # view only to IT team
    close = (('Closed', 'Closed'), ('Cancelled', 'Cancelled'), ('Open', 'Open'), ('Completed', 'Completed'))
    confirm = models.BooleanField(default=False)
    close_request = models.CharField(max_length=15, blank=True, choices=close, default='Open')
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


# many to many relation for users to make multiple requests
class user_request_table(models.Model):
    user_request = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_request_link')
    request_request = models.ForeignKey(request_table, on_delete=models.CASCADE, related_name='request_request_link')

    class Meta:
        verbose_name_plural = 'User_request_table'

    def __str__(self):
        return '{} | {}'.format(self.user_request.get_full_name, self.request_request.request)

# class response_time_table(models.Model):
