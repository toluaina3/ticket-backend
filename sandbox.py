from endpoints.serializers import ResponseTableApiSerializer
from django.utils import timezone
import requests
data = {'response': 'api testing', 'time_response': timezone.now()}
a = ResponseTableApiSerializer(data=data)
a.is_valid()
a.save()
print(a.data['response'])