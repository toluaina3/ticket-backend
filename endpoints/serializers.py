from verify.models import User
from rest_framework import serializers
from rest_framework_jwt.settings import api_settings
from request.models import bio, roles_table, permission, response_table

jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER


class UserApiSerialized(serializers.ModelSerializer):
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


class BioApiSerialized(serializers.ModelSerializer):
    bio_user_relation = UserApiSerialized(required=True)
    job_title = serializers.CharField(max_length=40)
    branch = serializers.CharField(max_length=20)
    department = serializers.CharField(max_length=30)
    phone = serializers.IntegerField(max_value=13)

    class Meta:
        model = bio
        fields = ['job_title', 'branch', 'phone', 'department', 'bio_user_relation']

    def create(self, validated_data):
        user_data = validated_data.pop('bio_user_relation')
        bio_user_relation = UserApiSerialized.create(UserApiSerialized(), validated_data=user_data)
        bio_link, created = bio.objects.update_or_create(bio_user=bio_user_relation,
                                                         job_title=validated_data.pop('job_title'),
                                                         branch=validated_data.pop('branch'),
                                                         phone=validated_data.pop('phone'),
                                                         department=validated_data.pop('department'))
        return bio_link, created


class RoleApiSerialized(serializers.ModelSerializer):
    role = serializers.CharField(max_length=15)

    class Meta:
        model = roles_table
        fields = ['role']


# many to many relational database
class PermissionApiSerializer(serializers.ModelSerializer):
    role_permit = RoleApiSerialized(required=True)
    user_permit = BioApiSerialized(required=True)

    class Meta:
        model = permission
        fields = ['user_permit', 'role_permit']

    def create(self, validated_data):
        user_data = validated_data.pop('user_permit')
        permit_user = BioApiSerialized.create(BioApiSerialized(), validated_data=user_data)
        role_data = validated_data.pop('role_permit')
        permit_user_role = RoleApiSerialized.create(RoleApiSerialized(), validated_data=role_data)
        permit_link, created = permission.objects.update_or_create(user_permit=permit_user,
                                                                   role_permit=permit_user_role)
        return permit_link, created


class ResponseTableApiSerializer(serializers.ModelSerializer):
    class Meta:
        model = response_table
        fields = ['response']


class ShowPublicUser(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'first_name']
