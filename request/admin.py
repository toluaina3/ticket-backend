from django.contrib import admin
from verify.models import User
from request.models import roles_table, permission, bio, request_table, \
    user_request_table, sla, priority_tables, custom_email_message

# Register your models here.
admin.site.register(roles_table)
admin.site.register(permission)
admin.site.register(bio)
admin.site.register(User)
admin.site.register(request_table)
admin.site.register(user_request_table)
admin.site.register(sla)
admin.site.register(priority_tables)
admin.site.register(custom_email_message)
