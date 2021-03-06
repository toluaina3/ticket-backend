"""clean_code URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, re_path, include
from django.conf import settings
import debug_toolbar

# if settings.DEBUG and 'debug_toolbar' in settings.INSTALLED_APPS:
urlpatterns = [
    path('ktull/', admin.site.urls),
    re_path(r'^', include('verify.urls')),
    re_path(r'^', include('request.urls')),
    re_path(r'^__debug__/', include(debug_toolbar.urls)),
    re_path(r'^endpoints/', include('endpoints.urls')),


]
