from endpoints.utils import jwt_response_payload_handler
from rest_framework_jwt.settings import api_settings
from rest_framework.authtoken.models import Token

jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER


def token_pass(user, request):
    payload = jwt_payload_handler(user)
    token = jwt_encode_handler(payload)
    talk, _ = Token.objects.get_or_create(user=user)
    return jwt_response_payload_handler(token, user, request=request)
