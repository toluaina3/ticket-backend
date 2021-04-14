from django.contrib.auth import login, logout
from rest_framework.response import Response
from rest_framework.generics import CreateAPIView, UpdateAPIView, ListAPIView
from rest_framework.views import APIView
from rest_framework.permissions import IsAdminUser, IsAuthenticated
from .permission import RegistrationPermission
from .serializers import PermissionApiSerializer, \
    UpdatePasswordSerialized, BioApiSerialized, \
    PasswordResetSerializer, LoginAPiSerializer, \
    List_ticketSerialized, TicketCreateSerialized, \
    SLACreateSerializer, SLAListSerialized, \
    PermissionApiSerializer2, UserPermitSerializer2, \
    Ticket_assign_task
from rest_framework import status, generics
from clean_code.tasks import send_mail_password_reset_api
from request.models import bio, User, roles_table, permission
from django.views.decorators.csrf import csrf_exempt
from rest_framework_jwt.authentication import JSONWebTokenAuthentication
from request.models import user_request_table, request_table, sla, permission
from clean_code.tasks import logging_info_task, send_mail_request_raised, \
    send_mail_request_raised_it_team, send_mail_task_assigned_started, \
    send_mail_task_completed_user, send_mail_task_cancelled_request
from cacheops import invalidate_model
from django.utils import timezone
from .functions.functions import token_pass


# API List view. use the serialized registration view below
class RegisterAPI(CreateAPIView):
    # the custom registration permission do not allow authenticated
    # user to re-register.
    permission_classes = [RegistrationPermission]
    serializer_class = PermissionApiSerializer

    def post(self, request, *args, **kwargs):
        serializer = PermissionApiSerializer(data=request.data)
        if serializer.is_valid(raise_exception=ValueError):
            serializer.create(validated_data=request.data)
            response = {'status': 'success',
                        'code': status.HTTP_201_CREATED,
                        'data': serializer.data}
            return Response(response)
        return Response(serializer.error_messages,
                        status=status.HTTP_400_BAD_REQUEST)


# API to create the user role, must be an admin
class CreateRole(CreateAPIView):
    permission_classes = [RegistrationPermission]
    serializer_class = BioApiSerialized

    def post(self, request, *args, **kwargs):
        serializer = BioApiSerialized(data=request.data)
        if serializer.is_valid(raise_exception=ValueError):
            serializer.create(validated_data=request.data)
            response = {'status': 'success',
                        'code': status.HTTP_201_CREATED,
                        'data': serializer.data}
            return Response(response)
        return Response(serializer.error_messages,
                        status=status.HTTP_400_BAD_REQUEST)


class ResetPassword(CreateAPIView):
    permission = [RegistrationPermission]
    serializer_class = PasswordResetSerializer

    def post(self, request, *args, **kwargs):
        serializer_email = PasswordResetSerializer(data=request.data)
        if serializer_email.is_valid(raise_exception=ValueError):
            if User.objects.filter(email=(request.data['email'])):
                get_user_pk = User.objects.filter(email=(request.data['email'])).values('user_pk')[0]['user_pk']
                send_mail_password_reset_api(user=get_user_pk)
                response = {'status': 'success',
                            'code': status.HTTP_201_CREATED,
                            'data': serializer_email.data}
                return Response(response)
            response = {'status': 'User does not Exists',
                        'code': status.HTTP_403_FORBIDDEN,
                        'data': serializer_email.data}
            return Response(response)
        return Response(serializer_email.error_messages,
                        status=status.HTTP_400_BAD_REQUEST)


class UpdatePassword(UpdateAPIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JSONWebTokenAuthentication]
    serializer_class = UpdatePasswordSerialized

    # get the user object
    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    @csrf_exempt
    def update(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid(raise_exception=ValueError):
            if not self.object.check_password(serializer.data.get("old_password")):
                response = {'status': 'Error',
                            'code': status.HTTP_400_BAD_REQUEST,
                            'message': 'Password not correct'}
                return response
            # set the user new password
            self.object.set_password(serializer.data.get('new_password'))
            self.object.save()
            response = {'status': 'Success',
                        'code': status.HTTP_201_CREATED,
                        'message': 'Password has been created'}
            return Response(response)
        return Response({'status': 'Error',
                         'code': status.HTTP_400_BAD_REQUEST,
                         'message': 'Password not created'})


class Login(APIView):
    serializer_class = LoginAPiSerializer

    @csrf_exempt
    def post(self, request):
        serializer = LoginAPiSerializer(data=request.data)
        if serializer.is_valid(raise_exception=ValueError):
            user = serializer.save(validated_data=request.data)
            login(request, user)
            red = token_pass(user=user, request=request)
            return Response({'token': red,
                             'code': status.HTTP_200_OK,
                             'status': 'success', 'message': '({}, logged in)'.format(request.user.get_full_name())})
        return Response('Invalid username and password try again')


class Logout(APIView):
    permission_classes = [IsAuthenticated]

    @csrf_exempt
    def post(self, request):
        logout(request=request)
        return Response({"success": "successfully logged out."},
                        status=status.HTTP_200_OK)


class list_ticket(ListAPIView):
    # authentication_classes = [JSONWebTokenAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = List_ticketSerialized

    def get_queryset(self):
        if self.request.user.permit_user.filter(role_permit__role='IT team').only().cache():
            query = user_request_table.objects.filter \
                (request_request__assigned_to=self.request.user.first_name + ' ' + self.request.user.last_name) \
                .order_by('-request_request__request_open').only()
            return query
        elif self.request.user.permit_user.filter(role_permit__role='User').only().cache():
            query = user_request_table.objects.filter \
                (user_request_id=self.request.user.user_pk) \
                .order_by('-request_request__request_open').only()
            return query
        elif self.request.user.permit_user.filter(role_permit__role='Admin').only().cache():
            query = user_request_table.objects.all() \
                .order_by('-request_request__request_open').only().cache()
            return query
        else:
            response = {'status': 'Role has not been assigned',
                        'code': status.HTTP_400_BAD_REQUEST}
            return Response(response)


class ticket_create(CreateAPIView):
    permission_classes = [IsAuthenticated]
    # authentication_classes = [JSONWebTokenAuthentication]
    serializer_class = TicketCreateSerialized
    lookup_field = 'pk'

    def post(self, request, *args, **kwargs):
        serializer = TicketCreateSerialized(data=request.data)
        if serializer.is_valid(raise_exception=ValueError):
            get_id = serializer.create(validated_data=request.data)
            # tie the ticket created to the user request
            user_request_table.objects.create(user_request_id=self.request.user.user_pk,
                                              request_request_id=get_id.id)
            response = {'status': 'success; ticket created',
                        'code': status.HTTP_201_CREATED,
                        'data': serializer.data}
            logging_info_task(msg='Request raised for the user {}'.format(self.request.user.get_full_name()))
            # send acknowledgment mail to user when request has been raised
            send_mail_request_raised(user=self.request.user.user_pk)
            # send mail to the ticket@team when request is raised
            send_mail_request_raised_it_team(user=self.request.user.user_pk)
            return Response(response)
        return Response(serializer.error_messages,
                        status=status.HTTP_400_BAD_REQUEST)


class sla_list(ListAPIView):
    permission_classes = [IsAuthenticated]
    # authentication_classes = [JSONWebTokenAuthentication]
    serializer_class = SLAListSerialized

    def get_queryset(self):
        if self.request.user.permit_user.filter(role_permit__role='Admin').only().cache():
            query = sla.objects.all().order_by('sla_category')
            return query
        else:
            message = 'No Data found'
            return message


class sla_create(CreateAPIView):
    permission_classes = [IsAuthenticated]
    # authentication_classes = [JSONWebTokenAuthentication]
    serializer_class = SLAListSerialized
    lookup_field = 'pk'

    def post(self, request, *args, **kwargs):
        if self.request.user.permit_user.filter(role_permit__role='Admin').only().cache():
            serializer = SLACreateSerializer(data=request.data)
            if serializer.is_valid(raise_exception=ValueError):
                serializer.create(validated_data=request.data)
                response = {'status': 'success: sla created',
                            'code': status.HTTP_201_CREATED,
                            'data': serializer.data}
                return Response(response)
            return Response(serializer.error_messages,
                            status=status.HTTP_400_BAD_REQUEST)
        else:
            response = {'status': 'error: Not a superuser',
                        'code': status.HTTP_403_FORBIDDEN}
            return Response(response)


class sla_update(UpdateAPIView):
    permission_classes = [IsAuthenticated]
    # authentication_classes = [JSONWebTokenAuthentication]
    serializer_class = SLAListSerialized
    lookup_field = 'pk'

    def put(self, request, *args, **kwargs):
        serializer = SLACreateSerializer(data=request.data)
        if serializer.is_valid(raise_exception=ValueError):
            self.get_serializer(validated_data=request.data, instance=request.data, partial=True)
            self.perform_update(serializer)
            response = {'status': 'success: sla updated',
                        'code': status.HTTP_201_CREATED,
                        'data': serializer.data}
            return Response(response)
        return Response(serializer.error_messages,
                        status=status.HTTP_400_BAD_REQUEST)


class user_management(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    # authentication_classes = [JSONWebTokenAuthentication]
    serializer_class = PermissionApiSerializer2

    def get_queryset(self):
        if self.request.user.is_superuser:
            query = permission.objects.all()
            return query
        else:
            response = {'status': 'error: Not a superuser',
                        'code': status.HTTP_403_FORBIDDEN}
            return Response(response)


class user_management_update(generics.UpdateAPIView, generics.RetrieveAPIView):
    permission_classes = [IsAuthenticated]
    # authentication_classes = [JSONWebTokenAuthentication]
    serializer_class = PermissionApiSerializer2
    lookup_field = 'user_permit'

    def get_queryset(self):
        if self.request.user.is_superuser:
            invalidate_model(bio)
            invalidate_model(roles_table)
            invalidate_model(User)
            invalidate_model(permission)
            query = permission.objects.all()
            return query
        else:
            response = {'status': 'User not found',
                        'code': status.HTTP_400_BAD_REQUEST}
            return Response(response)

    def put(self, request, *args, **kwargs):
        if self.request.user.is_superuser:
            serializer = PermissionApiSerializer2(data=self.request.data,
                                                  instance=self.get_object(), partial=True)
            query = bio.objects.filter(bio_user_id=self.request.data[
                'user_permit']['user_pk']).values('phone')[0]['phone']

            if query == serializer.initial_data['user_permit']['bio_user_relation']['phone']:
                role_update = roles_table.objects.filter \
                    (role=self.request.data['role_permit']['role']).values \
                    ('role_id')[0]['role_id']
                User.objects.filter(user_pk=self.request.data['user_permit']['user_pk']). \
                    update(first_name=self.request.data['user_permit'] \
                    ['first_name'], last_name=self.request.data['user_permit']['last_name'])
                bio.objects.filter(bio_user_id=self.request.data['user_permit']['user_pk']) \
                    .update(branch=self.request.data['user_permit']['bio_user_relation']['branch']
                            , department=self.request.data['user_permit']['bio_user_relation']['department']
                            , job_title=self.request.data['user_permit']['bio_user_relation']['phone'])
                permission.objects.filter(user_permit_id=self.request.data['user_permit']['user_pk']) \
                    .update(role_permit_id=role_update)
                response = {'status-1': 'success: user updated',
                            'code': status.HTTP_201_CREATED}
                return Response(response)

            elif query != serializer.initial_data['user_permit']['bio_user_relation']['phone']:
                if serializer.is_valid():
                    serializer.update(instance=self.get_object(), validated_data=self.request.data)
                    response = {'status': 'success: user updated',
                                'code': status.HTTP_201_CREATED,
                                'data': serializer.data}
                    return Response(response)
                return Response(serializer.error_messages,
                                status=status.HTTP_400_BAD_REQUEST)
        response = {'status': 'User not found',
                    'code': status.HTTP_400_BAD_REQUEST}
        return Response(response)


class user_management_deactivate(generics.RetrieveAPIView, generics.UpdateAPIView):
    # authentication_classes = [JSONWebTokenAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = UserPermitSerializer2
    lookup_field = 'user_pk'

    def get_queryset(self):
        if self.request.user.is_superuser:
            invalidate_model(User)
            queryset = User.objects.all()
            return queryset
        else:
            response = {'status': 'Not a superuser',
                        'code': status.HTTP_400_BAD_REQUEST}
            return Response(response)

    def update(self, request, *args, **kwargs):
        if self.request.user.is_superuser:
            if User.objects.get(user_pk=self.request.data['user_pk']):
                if User.objects.get(user_pk=self.request.data['user_pk']).is_active:
                    User.objects.filter \
                        (user_pk=self.request.data['user_pk']).update(is_active=False)
                    response = {'status': 'User deactivated successfully',
                                'code': status.HTTP_201_CREATED}
                    return Response(response)
                elif not User.objects.get(user_pk=self.request.data['user_pk']).is_active:
                    User.objects.filter \
                        (user_pk=self.request.data['user_pk']).update(is_active=True)
                    response = {'status': 'User activated successfully',
                                'code': status.HTTP_201_CREATED}
                    return Response(response)
            else:
                response = {'status': 'User not found',
                            'code': status.HTTP_400_BAD_REQUEST}
                return Response(response)


class Ticket_assign(generics.UpdateAPIView, generics.RetrieveAPIView):
    # authentication_classes = [JSONWebTokenAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = Ticket_assign_task
    lookup_field = 'id'

    def get_queryset(self):
        invalidate_model(request_table)
        queryset = request_table.objects.all()
        return queryset

    def put(self, request, *args, **kwargs):
        requester_id = user_request_table.objects \
            .get(request_request_id=self.request.data['id']).user_request.user_pk
        if self.request.data['assigned_to'] is None:
            response = {'status': 'You must assign ticket to a user',
                        'code': status.HTTP_400_BAD_REQUEST}
            return Response(response)
        elif self.request.data['assigned_to'] is not None:
            if self.request.data['close_request'] == 'Started':
                request_table.objects.filter \
                    (id=self.request.data['id'].update(request_time_started=timezone.now(),
                                                       close_request='Started',
                                                       assigned_to=self.request.data['assigned_to'],
                                                       copy_team=self.request.data['copy_team']))
                # task, send email to the user and the assignee
                send_mail_task_assigned_started(assign=self.request.data['assigned_to'], user=requester_id)
                response = {'status': 'Ticket successfully started',
                            'code': status.HTTP_201_CREATED}
                return Response(response)
            elif self.request.data['close_request'] == 'Completed':
                request_table.objects.filter \
                    (id=self.request.data['id'].update(request_time_closed=timezone.now(),
                                                       close_request='Completed',
                                                       assigned_to=self.request.data['assigned_to'],
                                                       copy_team=self.request.data['copy_team']))
                # task send a completion email to the user and the assignee
                send_mail_task_completed_user(assign=self.request.data['assigned_to'],
                                              user=requester_id)
                response = {'status': 'Ticket successfully completed',
                            'code': status.HTTP_201_CREATED}
                return Response(response)
            elif self.request.data['close_request'] == 'Cancelled':
                request_table.objects.filter \
                    (id=self.request.data['id'].update(request_time_updated=timezone.now(),
                                                       close_request='Cancelled',
                                                       assigned_to=self.request.data['assigned_to'],
                                                       copy_team=self.request.data['copy_team']))
                send_mail_task_cancelled_request(user=requester_id)
                response = {'status': 'Ticket successfully cancelled',
                            'code': status.HTTP_201_CREATED}
                return Response(response)
