from django.urls import re_path
from django.conf import settings
from endpoints import views


if settings.DEBUG and 'debug_toolbar' in settings.INSTALLED_APPS:
    urlpatterns = [
        re_path(r'^register/$', views.ResponseAPI.as_view(), name='user-management'),
        ]