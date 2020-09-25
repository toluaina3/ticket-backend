from __future__ import unicode_literals
from django.db import models
from django.core.mail import send_mail
from django.contrib.auth.models import PermissionsMixin, AbstractBaseUser, BaseUserManager
from django.utils.translation import ugettext_lazy as _
import jwt
from datetime import datetime, timedelta
from django.conf import settings


class UserManager(BaseUserManager):
    # use_in_migrations = True
    def create_user(self, email, first_name, last_name, password=None, commit=True):
        # create and save User with email and password
        if not email:
            raise ValueError(_('Enter a valid email'))
        if not first_name:
            raise ValueError(_('Enter your First Name'))
        if not last_name:
            raise ValueError(_('Enter your Last Name'))
        user = self.model(
            email=self.normalize_email(email),
            first_name=first_name,
            last_name=last_name
        )
        user.set_password(password)
        if commit:
            user.save(using=self.db)
        return user

    # create the superuser
    def create_superuser(self, email, first_name, last_name, password):
        # call the instance of the function create user.
        user = self.create_user(
            email,
            first_name=first_name,
            last_name=last_name,
            password=password,
            commit=False,
        )

        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user


# Create your models here.
class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(verbose_name=_('Email Address'), unique=True, max_length=100)
    first_name = models.CharField(_('First Name'), max_length=30, blank=True)
    last_name = models.CharField(_('Last Name'), max_length=30, blank=True)
    date_joined = models.DateTimeField(_('Date Joined'), auto_now_add=True)
    last_login = models.DateTimeField(_('Last Login'), auto_now=True)
    is_active = models.BooleanField(_('Active'), default=True, help_text='The user should be active or not')
    is_staff = models.BooleanField(_('IT Team'), default=False, help_text='IT Team')

    objects = UserManager()
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    class Meta:
        verbose_name = 'User'
        verbose_name_plural = 'Users'

    def get_full_name(self):
        # Returns the first_name plus the last_name, with a space in between.
        full_name = '%s %s' % (self.first_name, self.last_name)
        return full_name.strip()

    def get_short_name(self):
        # Returns the short name for the user.
        return self.first_name

    def __str__(self):
        return '{} <{}> '.format(self.get_full_name(), self.email)

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return True

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True

    def email_user(self, subject, message, from_email=None, **kwargs):
        # Sends an email to this User.
        send_mail(subject, message, from_email, [self.email], **kwargs)

    @property
    def token(self):
        """
        Allows us to get a user's token by calling `user.token` instead of
        `user.generate_jwt_token().

        The `@property` decorator above makes this possible. `token` is called
        a "dynamic property".
        """
        return self._generate_jwt_token()

    def _generate_jwt_token(self):
        """
        Generates a JSON Web Token that stores this user's ID and has an expiry
        date set to 60 days into the future.
        """
        dt = datetime.now() + timedelta(days=30)

        token = jwt.encode({
            'id': self.pk,
            'exp': int(dt.strftime('%s'))
        }, settings.SECRET_KEY, algorithm='HS256')
        return token.decode('utf-8')
