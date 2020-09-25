from django.contrib import admin
from verify.models import User
from request.models import roles_table, permission, bio

# Register your models here.
admin.site.register(roles_table)
admin.site.register(permission)
admin.site.register(bio)
admin.site.register(User)
