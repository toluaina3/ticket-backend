from rest_framework import permissions


# user can not register if authenticated
class RegistrationPermission(permissions.BasePermission):
    # the message function overrides the default detail message
    message = 'Passed authentication, can not re-register'

    def has_permission(self, request, view):
        return not request.user.is_authenticated


class IsOwnerOrReadOnly(permissions.BasePermission):
    message = 'You do not own this account, edit disabled'

    # the methods call that only register user can edit the view
    def has_object_permission(self, request, view, obj):
        if request.method == permissions.SAFE_METHODS:
            return True
        # if the object call is the user, perform the edit function
        if obj.user == request.user:
            return True
