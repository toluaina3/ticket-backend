"""
Django settings for clean_code project.

Generated by 'django-admin startproject' using Django 3.1.

For more information on this file, see
https://docs.djangoproject.com/en/3.1/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/3.1/ref/settings/
"""
import os
import environ
from requests import ConnectionError

env = environ.Env()
# reading .env file
environ.Env.read_env()

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/3.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = env('SECRET_KEY')
AUTH_USER_MODEL = 'verify.User'
CRISPY_TEMPLATE_PACK = 'bootstrap4'
SESSION_EXPIRE_AT_BROWSER_CLOSE = True

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['127.0.0.1', '192.100.0.4']
INTERNAL_IPS = '127.0.0.1'

# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'verify',
    'request',
    'clean_code',
    'django.contrib.humanize',
    'cacheops',
    'debug_toolbar',
    'crispy_forms',
    'django_celery_beat',


]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    # 'django.middleware.cache.UpdateCacheMiddleware',  # middleware to update cache table
    'django.middleware.common.CommonMiddleware',
    # 'django.middleware.cache.FetchFromCacheMiddleware',   # middleware to fetch from cache table
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'debug_toolbar.middleware.DebugToolbarMiddleware',
]

ROOT_URLCONF = 'clean_code.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates'),
                 os.path.join(BASE_DIR, 'verify/pages'), os.path.join(BASE_DIR, 'request/pages'), ]
        ,
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',

            ],
        },
    },
]

WSGI_APPLICATION = 'clean_code.wsgi.application'

# Database
# https://docs.djangoproject.com/en/3.1/ref/settings/#databases

# postgres container
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': env('DATABASE_NAME'),  # mysql code, port 3306  #callapp
        'USER': env('DATABASE_USER'),
        'PASSWORD': env('DATABASE_PASSWORD'),
        'HOST': env('DATABASE_HOST'),
        'PORT': '5432',
        'ATOMIC_REQUESTS': True,

    }
}

# default number of seconds to cache a page
# CACHE_MIDDLEWARE_SECONDS = 120
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': env('REDIS_LOCATION'),
        'OPTIONS': {
            'DB': 1,
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
            # config set requirepass $$ticket
            #  ./manage.py invalidate auth.user
            'PASSWORD': '$$ticket',  # password remove $$ sign
            'KEY_PREFIX': '$@ticket',
        }
    }
}

CACHEOPS_REDIS = {
    'host': env('REDIS_HOST'),
    'port': '6379',
    'db': 1,
    'password': '$$ticket',

}
CACHEOPS_DEGRADE_ON_FAILURE = True

CACHEOPS = {
    # cache `user model` get queries for 1 hour
    'verify.User': {'ops': ('fetch', 'get'), 'timeout': 60 * 60},
    # cache `user role` and `permission` get queries for 15 minutes
    'request.roles_table': {'ops': ('fetch', 'get'), 'timeout': 60 * 15},
    # cache bio database queries for 15 minute
    'request.bio': {'ops': 'get', 'timeout': 60 * 15},
    # cache the user request for 1 hour
    'request.request_table': {'ops': 'get', 'timeout': 60 * 60 * 1},
    # cache permission database queries for 1 day
    'request.permission': {'ops': 'get', 'timeout': 60 * 60 * 24},
    # cache the user request for 1 hour
    'request.user_request_table': {'ops': ('fetch', 'get'), 'timeout': 60 * 60 * 1},
    # cache the sla for 1 hour
    'request.sla': {'ops': ('fetch', 'get'), 'timeout': 60 * 60 * 5},

}

# django redis session
SESSION_ENGINE = 'redis_sessions.session'

SESSION_REDIS = {
    'host': env('REDIS_HOST'),
    'port': 6379,
    'db': 1,
    'password': '$$ticket',
    'prefix': 'session',
    'socket_timeout': 1
}

# Password validation
# https://docs.djangoproject.com/en/3.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
# https://docs.djangoproject.com/en/3.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'Africa/Lagos'

USE_I18N = True

USE_L10N = True

USE_TZ = True

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/3.1/howto/static-files/
STATIC_URL = '/static/'
STATICFILES_DIRS = os.path.join(BASE_DIR, 'static'),
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')
MEDIA_URL = '/media/'

try:
    EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
except ConnectionError:
    EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_HOST_USER = env('EMAIL_HOST')
EMAIL_HOST_PASSWORD = env('EMAIL_PASSWORD')
EMAIL_USE_TLS = True
DEFAULT_FROM_EMAIL = 'Ticket by IT Team <noreply@ticket.com>'


