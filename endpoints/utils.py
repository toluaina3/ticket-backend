from django.conf import settings
from datetime import datetime
from django.utils import timezone

expiry_date = settings.JWT_AUTH['JWT_EXPIRATION_DELTA']


# call the in-built user from the function
def jwt_response_payload_handler(token, user=None, request=None):
    return {
        'token': token,
        'user': user.get_full_name(),
        'Token Expires': timezone.now() + expiry_date,
    }
