from rest_framework.views import APIView
from django.contrib.auth import authenticate, login, logout
from rest_framework.response import Response
from verify.models import User
from request.models import response_table
from rest_framework.generics import CreateAPIView
from .permission import RegistrationPermission
from .utils import jwt_response_payload_handler
from .serializers import ResponseTableApiSerializer, BioApiSerialized
from rest_framework_jwt.settings import api_settings
from django.utils import timezone
from rest_framework import status


# API List view. use the serialized registration view below
class ResponseAPI(APIView):
    # the custom registration permission do not allow authenticated
    # user to re-register.
    permission_classes = [RegistrationPermission]

    def post(self, request):
        serializer = BioApiSerialized(data=request.data)
        if serializer.is_valid(raise_exception=ValueError):
            serializer.create(validated_data=request.data)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.error_messages,
                        status=status.HTTP_400_BAD_REQUEST)
