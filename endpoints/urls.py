from django.urls import re_path
from django.conf import settings
from endpoints import views


if settings.DEBUG and 'debug_toolbar' in settings.INSTALLED_APPS:
    urlpatterns = [
        re_path(r'^register/$', views.RegisterAPI.as_view(), name='register-user'),
        re_path(r'^role/$', views.CreateRole.as_view(), name='create-role'),
        ]