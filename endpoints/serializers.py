from verify.models import User
from rest_framework import serializers
#from rest_framework_jwt.settings import api_settings


class ShowPublicUser(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'first_name']


class RegisterApiSerialized(serializers.ModelSerializer):
    # read only the password field
    password = serializers.CharField(style={'input': 'password'}, write_only=True)
    password2 = serializers.CharField(style={'input': 'password'}, write_only=True)
    first_name = serializers.CharField(style={'input': 'password'}, write_only=True)
    last_name = serializers.CharField(style={'input': 'password'}, write_only=True)
    token = serializers.SerializerMethodField(style={'input': 'password'}, read_only=True)

    class Meta:
        model = User
        fields = ['email',
                  'password',
                  'password2',
                  'first_name',
                  'last_name',
                  'token',

                  ]
        extra_kwargs = {'password': {'write_only': True}}

    def validate(self, data):
        pw = data.get('password')
        pw2 = data.pop('password2')
        if pw != pw2:
            raise serializers.ValidationError('Password do not match')
        return data

    def create(self, validated_data):
        validate_user = User.objects.create(email=validated_data.get('email'),
                                            first_name=validated_data.get('first_name'),
                                            last_name=validated_data.get('last_name'))
        # validate the password, and call set_password
        validate_user.set_password(validated_data.get('password'))
        validate_user.save()
        return validate_user

    @staticmethod
    def get_token(obj=User):
        user = obj
        payload = jwt_payload_handler(user)
        token = jwt_encode_handler(payload)
        return token
