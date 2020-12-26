from django.urls import re_path
from django.conf import settings
from request import views
from django.contrib.auth.decorators import login_required

if settings.DEBUG and 'debug_toolbar' in settings.INSTALLED_APPS:
    urlpatterns = [
        re_path(r'^user-management/$', login_required(views.user_management_view.as_view(),
                                                      login_url='/login',
                                                      redirect_field_name='pass'), name='user-management'),
        re_path(r'^user/update/(?P<pk>[-\w\d]+)$', views.update_user_management,
                name='update-user-management'),
        re_path(r'^user/active/(?P<pk>[-\w\d]+)$', views.deactivate_user, name='user-active'),
        re_path(r'^request/$', views.requests_view, name='request'),
        re_path(r'^request/create/(?P<pk>[-\w\d]+)$', views.requests_user_create, name='request-create'),
        re_path(r'^request/list/(?P<pk>[-\w\d]+)$', views.list_user_request, name='request-list'),
        re_path(r'^request/assign/(?P<pk>[-\w\d]+)$', views.assign_task, name='assign-task'),
        re_path(r'^request/confirmed/(?P<pk>[-\w\d]+)$', views.user_confirm_request, name='user-confirm'),
        re_path(r'^request/sla/create/$', views.sla_create, name='sla-create'),
        re_path(r'^request/sla/view/$', views.sla_view, name='sla-view'),
        re_path(r'^request/sla/update/(?P<pk>[-\w\d]+)$', views.sla_update, name='sla-update'),
        re_path(r'^request/search/', views.search_request_list_query, name='request-search'),
        re_path(r'^request/sla/delete/$', views.sla_delete, name='sla-delete'),
        re_path(r'^request/ticket/message/(?P<pk>[-\w\d]+)$', views.request_response, name='ticket-message'),
        re_path(r'^request/ticket/message/compose/(?P<pk>[-\w\d]+)$', views.compose_response, name='ticket-compose'),
        re_path(r'^request/ticket/logs/(?P<pk>[-\w\d]+)$', views.request_time_log, name='ticket-log'),

    ]
