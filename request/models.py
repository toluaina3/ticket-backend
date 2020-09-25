from django.db import models
from verify.models import User
import uuid


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
    role_permit = models.ForeignKey(roles_table, on_delete=models.CASCADE, related_name='permit_user')

    class Meta:
        verbose_name_plural = 'permissions'

    def __str__(self):
        return str(self.user_permit)
