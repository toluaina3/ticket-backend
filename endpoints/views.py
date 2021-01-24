from rest_framework.views import APIView
from django.contrib.auth import authenticate, login, logout
from rest_framework.response import Response
from verify.models import User
from request.models import response_table
from rest_framework.generics import CreateAPIView
from .permission import RegistrationPermission
from .utils import jwt_response_payload_handler
from .serializers import PermissionApiSerializer, RoleApiSerialized
from rest_framework_jwt.settings import api_settings
from django.utils import timezone
from rest_framework import status
from django.contrib import messages


# API List view. use the serialized registration view below
class RegisterAPI(CreateAPIView):
    # the custom registration permission do not allow authenticated
    # user to re-register.
    permission_classes = [RegistrationPermission]
    serializer_class = PermissionApiSerializer


'''
    def post(self, request):
        serializer = PermissionApiSerializer(data=request.data)
        if serializer.is_valid(raise_exception=ValueError):
            serializer.create(validated_data=request.data)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.error_messages,
                        status=status.HTTP_400_BAD_REQUEST)
'''


# API to create the user role
class CreateRole(CreateAPIView):
    permission_classes = [RegistrationPermission]
    serializer_class = RoleApiSerialized
