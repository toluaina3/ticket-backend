from django.urls import path, re_path
from verify import views as verify
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.contrib.auth import views as auth_views

#if settings.DEBUG and 'debug_toolbar' in settings.INSTALLED_APPS:
urlpatterns = [
        re_path(r'^login/$', verify.login_view, name='login'),
        re_path(r'^home/$', login_required(verify.login_home, login_url='/login', redirect_field_name='pass'),
                name='home'),
        re_path(r'^logout/$', login_required(verify.log_out, login_url='/login', redirect_field_name='pass'),
                name='logout'),
        re_path(r'^register/$', login_required(verify.register_user,
                                               login_url='/login', redirect_field_name='pass'), name='register'),

        re_path(r'^password_reset/$',
                verify.password_reset_request, name='password_reset'),
        re_path(r'^password_reset/done/$',
                auth_views.PasswordResetDoneView.as_view(template_name='password/password_reset_done.html'),
                name='password_reset_done'),
        path('reset/<uidb64>/<token>/',
             auth_views.PasswordResetConfirmView.as_view(template_name="password/password_reset_confirm.html"),
             name='password_reset_confirm'),
        re_path(r'^reset/done/$',
                auth_views.PasswordResetCompleteView.as_view(template_name='password/password_reset_complete.html'),
                name='password_reset_complete'),

    ]
