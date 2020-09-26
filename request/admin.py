from django.contrib import admin
from verify.models import User
from request.models import roles_table, permission, bio, request_table, user_request_table

# Register your models here.
admin.site.register(roles_table)
admin.site.register(permission)
admin.site.register(bio)
admin.site.register(User)
admin.site.register(request_table)
admin.site.register(user_request_table)
