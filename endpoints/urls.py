from django.urls import re_path
from django.conf import settings
from endpoints import views


if settings.DEBUG and 'debug_toolbar' in settings.INSTALLED_APPS:
    urlpatterns = [
        re_path(r'^register$', views.RegisterAPI.as_view(), name='register-user'),
        re_path(r'^role/$', views.CreateRole.as_view(), name='get-role'),
        re_path(r'^password/reset$', views.ResetPassword.as_view(), name='reset-password'),
        re_path(r'^login/$', views.Login.as_view(), name='login'),
        re_path(r'^logout/$', views.Logout.as_view(), name='logout'),
        re_path(r'^password/update/$', views.UpdatePassword.as_view(), name='reset-password'),
        re_path(r'^ticket/list/$', views.list_ticket.as_view(), name='ticket-list'),
        re_path(r'^ticket/create/(?P<pk>[-\w\d]+)/$', views.ticket_create.as_view(), name='ticket-create'),
        re_path(r'^sla/list/$', views.sla_list.as_view(), name='sla-list'),
        re_path(r'^sla/create/(?P<pk>[-\w\d]+)/$', views.sla_create.as_view(), name='sla-create'),
        re_path(r'^sla/update/(?P<pk>[-\w\d]+)/$', views.sla_update.as_view(), name='sla-update'),
        re_path(r'^user-management/list/$', views.user_management.as_view(),
                name='user-management-list'),
        re_path(r'^user-management/update/(?P<user_permit>[-\w\d]+)/$', views.user_management_update.as_view(),
                name='user-management-update'),
        re_path(r'^user-management/active/(?P<user_pk>[-\w\d]+)/$', views.user_management_deactivate.as_view(),
                name='user-management-activate'),
        ]