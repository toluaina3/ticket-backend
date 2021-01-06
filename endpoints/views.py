from rest_framework.views import APIView
from django.contrib.auth import authenticate, login, logout
from rest_framework.response import Response
from verify.models import User
from request.models import response_table
from rest_framework.generics import CreateAPIView
from .permission import RegistrationPermission
from .utils import jwt_response_payload_handler
from .serializers import RegisterApiSerialized, ResponseTableApiSerializer
from rest_framework_jwt.settings import api_settings
from django.utils import timezone


# API List view. use the serialized registration view below
class ResponseAPI(APIView):
    # the custom registration permission do not allow authenticated
    # user to re-register.
    permission_classes = [RegistrationPermission]

    def post(self, request, *args, **kwargs):
        #data = request.data
        rest = get(request)
        response = ResponseTableApiSerializer(rest)
        if response.is_valid():
            user = response_table.objects.create(response=response.data, time_response=timezone.now())
            user.save()
            return Response({'ok': 'yes get'}, status=201)
        else:
            return Response({'save': 'Not saved'}, status=401)
