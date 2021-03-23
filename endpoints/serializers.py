from verify.models import User
from rest_framework import serializers
from rest_framework_jwt.settings import api_settings
from request.models import bio, roles_table, permission, response_table, \
    request_table, user_request_table, sla, priority_tables
from django.contrib.auth import authenticate, login, logout
from drf_writable_nested.serializers import WritableNestedModelSerializer, \
    NestedUpdateMixin

jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER


class UserApiSerialized(serializers.ModelSerializer):
    # read only the password field
    password = serializers.CharField(style={'input': 'password'}, write_only=True)
    email = serializers.CharField(style={'input': 'password'}, write_only=True)
    password2 = serializers.CharField(style={'input': 'password'}, write_only=True)
    first_name = serializers.CharField(style={'input': 'password'}, write_only=True)
    last_name = serializers.CharField(style={'input': 'password'}, write_only=True)
    token = serializers.SerializerMethodField(style={'input': 'password'}, read_only=True)
    ticket_by = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = User
        fields = ['email',
                  'password',
                  'password2',
                  'first_name',
                  'last_name',
                  'token',
                  'ticket_by',

                  ]
        extra_kwargs = {'password': {'write_only': True}}

    def validate(self, data):
        pw = data.get('password')
        pw2 = data.pop('password2')
        if pw != pw2:
            raise serializers.ValidationError('Password do not match')
        if User.objects.filter(email=data.get('email', '')).exists():
            raise serializers.ValidationError({'email': 'Email is already in use'})
        return super().validate(data)

    def create(self, validated_data):
        # update or create returned no set_password attribute
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

    @staticmethod
    def get_ticket_by(obj=User):
        user = obj
        ticket_by = user.first_name + ' ' + user.last_name
        return ticket_by


class BioApiSerialized(serializers.ModelSerializer):
    bio_user_relation = UserApiSerialized(required=True)

    class Meta:
        model = bio
        fields = ['job_title', 'branch', 'phone', 'department', 'bio_user_relation']

    def create(self, validated_data):
        user_data = validated_data.pop('bio_user_relation')
        bio_user_relation = UserApiSerialized.create(UserApiSerialized(), validated_data=user_data)
        bio_link, created = bio.objects.update_or_create(bio_user=bio_user_relation,
                                                         job_title=validated_data.get('job_title'),
                                                         branch=validated_data.get('branch'),
                                                         phone=validated_data.get('phone'),
                                                         department=validated_data.get('department'))
        return bio_link, created


class RoleApiSerialized(serializers.ModelSerializer):
    role = serializers.ChoiceField(choices=roles_table.role_choices)

    class Meta:
        model = roles_table
        fields = ['role', 'role_id']


# many to many relational database
# using the related_name for the nested fields
class PermissionApiSerializer(serializers.ModelSerializer):
    permit_user_role = RoleApiSerialized(required=True)
    permit_user = BioApiSerialized(required=True)

    class Meta:
        model = permission
        fields = ['permit_user', 'permit_user_role']

    def create(self, validated_data):
        role_data = validated_data.get('permit_user_role')
        query = role_data['role']
        query_fill = roles_table.objects.filter(role=query).values('role_id')[0]['role_id']
        user_data = validated_data.pop('permit_user')
        # user pk must be gotten from the serialized data, then save into the bio_user_id as a valid uuid
        user_create = UserApiSerialized.create(UserApiSerialized(), validated_data=user_data['bio_user_relation'])
        care_bio = bio.objects.create(bio_user=user_create,
                                      job_title=user_data['job_title'], branch=user_data['branch'],
                                      phone=user_data['phone'], department=user_data['department'])
        care_bio.save()
        user_id_get = care_bio.bio_user.user_pk
        permit_user = permission.objects.update_or_create(user_permit_id=user_id_get,
                                                          role_permit_id=query_fill)
        return permit_user


class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()


class LoginAPiSerializer(serializers.ModelSerializer):
    email = serializers.CharField()
    password = serializers.CharField()

    class Meta:
        model = User
        fields = ['email', 'password']

    def save(self, **kwargs):
        email = self.validated_data.get('email')
        password = self.validated_data.get('password')
        if email and password:
            user = authenticate(email=email, password=password)
            if user:
                if user.is_active:
                    return user
                raise serializers.ValidationError({'user': 'User is not active'})
            elif not user:
                raise serializers.ValidationError({'user': 'Email or Password not correct*, try again'})
        raise serializers.ValidationError({'user': 'Email or Password not correct*, try again'})


class ShowPublicUser(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'first_name']


class UpdatePasswordSerialized(serializers.ModelSerializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['old_password', 'new_password', 'confirm_password']

    def validate(self, data):
        pw = data.get('new_password')
        pw2 = data.pop('confirm_password')
        if pw != pw2:
            raise serializers.ValidationError('Password do not match')
        return data


class PrioritySerializer(serializers.ModelSerializer):
    class Meta:
        priority_field = serializers.ChoiceField(choices=priority_tables.priority_choice)
        model = priority_tables
        fields = ['priority_field']


class SLASerializer(serializers.ModelSerializer):
    sla_priority = PrioritySerializer()

    class Meta:
        model = sla
        fields = ['sla_category', 'sla_priority']


class RequestTableSerialized(serializers.ModelSerializer):
    sla_category = SLASerializer()

    class Meta:
        model = request_table
        fields = ['ticket_number', 'assigned_to',
                  'copy_team', 'close_request',
                  'request_open', 'confirm', 'sla_category']


class List_ticketSerialized(serializers.ModelSerializer):
    request_request = RequestTableSerialized()
    user_request = UserApiSerialized()

    class Meta:
        model = user_request_table
        fields = ['request_request', 'user_request']


class Retrieve_ticketSerialized(serializers.ModelSerializer):
    request_request = RequestTableSerialized()
    user_request = UserApiSerialized()

    class Meta:
        model = user_request_table
        fields = ['request_request', 'user_request']


class PriorityCreateSerializer(serializers.ModelSerializer):
    priority_field = serializers.ChoiceField(priority_tables.priority_choice)

    class Meta:
        model = priority_tables
        fields = ['priority_field']


class SLACreateSerializer(serializers.ModelSerializer):
    sla_category = serializers.CharField(required=True)
    sla_time = serializers.IntegerField(required=True)
    sla_priority = PriorityCreateSerializer(required=True)

    class Meta:
        model = sla
        fields = ['sla_category', 'sla_time', 'sla_priority']

    def create(self, validated_data):
        priority_get = validated_data.get('sla_priority')
        priority_get_id = priority_get['priority_field']
        query_fill = priority_tables.objects.filter(priority_field=priority_get_id).values('priority_pk')[0][
            'priority_pk']
        query_sla = sla.objects.update_or_create(sla_category=validated_data.get('sla_category'),
                                                 sla_time=validated_data.get('sla_time'),
                                                 sla_priority_id=query_fill)

        return query_sla


class SLAListSerialized(serializers.ModelSerializer):
    sla_priority = PrioritySerializer()

    class Meta:
        model = sla
        fields = ['sla_category', 'sla_time', 'sla_priority', 'id']


class TicketCreateSerialized(serializers.ModelSerializer):
    choice = [(sla.sla_category, sla.sla_category)
              for sla in (sla.objects.all().order_by('sla_category').only())]
    request = serializers.CharField(required=True)
    request_category = serializers.ChoiceField(choices=choice)

    class Meta:
        model = request_table
        fields = ['request', 'request_category']

    def create(self, validated_data):
        category_get = validated_data.get('request_category')
        query_fill = sla.objects.filter(sla_category=category_get).values('id')[0][
            'id']
        request_user = request_table.objects.create(request=validated_data.get('request'), sla_category_id=query_fill)
        request_user.save()
        return request_user


class BioSerializer(serializers.ModelSerializer):
    class Meta:
        model = bio
        fields = ['job_title', 'branch', 'phone', 'department']


class UserPermitSerializer(serializers.ModelSerializer):
    bio_user_relation = BioSerializer()

    class Meta:
        model = User
        fields = ['user_pk', 'first_name', 'last_name', 'bio_user_relation']


class PermissionApiSerializer2(serializers.ModelSerializer):
    role_permit = RoleApiSerialized(required=True)
    user_permit = UserPermitSerializer(required=True)

    class Meta:
        model = permission
        fields = ['role_permit', 'user_permit']

    def update(self, instance, validated_data):
        bio_key = validated_data['user_permit']['bio_user_relation']
        user_key = validated_data['user_permit']
        instance_phone = self.instance.user_permit.bio_user_relation.phone
        inty = instance.role_permit

        if instance_phone != bio_key['phone']:
            role_update = RoleApiSerialized.update(RoleApiSerialized(), instance=inty,
                                                   validated_data=validated_data['role_permit'])
            User.objects.filter(user_pk=self.instance.user_permit.user_pk). \
                update(first_name=user_key['first_name'], last_name=user_key['last_name'])
            bio.objects.filter(bio_user_id=self.instance.user_permit.user_pk) \
                .update(branch=bio_key['branch'], department=bio_key['department']
                        , job_title=bio_key['job_title'], phone=bio_key['phone'])
            result = permission.objects.filter(permission_id=self.instance.user_permit.user_pk) \
                .update(role_permit_id=role_update)
            return result


class UserPermitSerializer2(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['user_pk', 'first_name', 'last_name', 'is_active']
