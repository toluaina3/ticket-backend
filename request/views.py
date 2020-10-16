from django.shortcuts import render, redirect, get_list_or_404, get_object_or_404, reverse
from verify.models import User
from request.models import permission
from django.views.generic.list import ListView
from verify.forms import UpdateBioForms, RoleForm
from .models import bio, roles_table, user_request_table, request_table
from django.contrib import messages
from django.db import transaction
from django.db.models import Q
from verify.forms import Request_Forms, Assign_Forms
from cacheops import invalidate_model, invalidate_obj
from clean_code.tasks import send_mail_request_raised, send_mail_request_raised_it_team, logging_info_task
from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage


# Create your views here.

class user_management_view(ListView):
    model = permission
    paginate_by = 8
    template_name = 'user_management_list.html'
    ordering = 'user_permit__first_name'
    context_object_name = 'user_query'


def update_user_management(request, pk=None):
    if not request.user.is_authenticated:
        return redirect('login')
    get_pk = get_object_or_404(User, pk=pk)
    if request.method == 'POST':
        form_two = RoleForm(request.POST)
        form_three = UpdateBioForms(request.POST)
        if form_two.is_valid() and form_three.is_valid():
            with transaction.atomic():
                try:
                    # create the forms instance on the database
                    post_two = (form_two.data['role'])
                    post_three = form_three.save(commit=False)
                    get_role = roles_table.objects.get(role=post_two)
                    # invalidate models before update signal
                    invalidate_model(bio, using=bio)
                    bio.objects.filter(Q(bio_user_id=get_pk)).update(branch=post_three.branch,
                                                                     department=post_three.department)
                    permission.objects.filter(Q(user_permit_id=get_pk)).update(role_permit_id=get_role.pk)
                    messages.success(request, '{}, was successfully Updated'.
                                     format(get_pk.first_name + ' ' + get_pk.last_name))
                    return redirect('user-management')
                except ConnectionError:
                    messages.error(request, 'Database Error')
        else:
            messages.error(request, 'User info can not update')
            return redirect('user-management')
    else:
        form_two = RoleForm(instance=roles_table.objects.get(permit_user_role__user_permit_id=get_pk))
        form_three = UpdateBioForms(instance=get_pk.bio_user_relation)
        context = {'form_two': form_two, 'form_three': form_three, 'get_pk': get_pk}
        return render(request, 'update_user_management.html', context=context)


def deactivate_user(request, pk=None):
    if not request.user.is_authenticated:
        return redirect('user-management')
    get_pk = get_object_or_404(User, pk=pk)
    if request.method == 'POST' or 'GET':
        if User.objects.get(email__exact=get_pk.email).is_active is not None:
            # invalidate_model(User, using=User)
            User.objects.filter(user_pk=get_pk.user_pk).update(is_active=False)
            invalidate_model(User)
            messages.success(request, 'User has been deactivated')
            logging_info_task(msg='{} has been deactivated'.format(get_pk.get_full_name))
            return redirect('user-management')
        elif not User.objects.get(email__exact=get_pk.email).is_active:
            User.objects.filter(user_pk=get_pk.user_pk).update(is_active=True)
            invalidate_model(User)
            messages.success(request, 'User has been activated')
            logging_info_task(msg='{} has been activated'.format(get_pk.get_full_name))
            return redirect('user-management')
    else:
        messages.error(request, 'Request Error')
        return redirect('user-management')


def requests_view(request):
    if not request.user.is_authenticated:
        return redirect('login')
    data = request.user.pk
    context = {'data': data}
    return render(request, 'request_view.html', context)


def requests_user_create(request, pk=None):
    if not request.user.is_authenticated:
        return redirect('login')
    get_pk = get_object_or_404(User, pk=pk)
    if request.method == 'POST':
        forms = Request_Forms(request.POST)
        if forms.is_valid():
            post = forms.save(commit=False)
            post.save()
            user_request_table.objects.create(user_request_id=get_pk.user_pk, request_request_id=post.id)
            post.save()
            messages.success(request, 'Request has been Submitted')
            # task of logged message
            logging_info_task(msg='Request raised for the user {}'.format(request.user.get_full_name))
            # send acknowledgment mail to user when request has been raised
            send_mail_request_raised(user=get_pk.user_pk)
            # send mail to the ticket@team when request is raised
            send_mail_request_raised_it_team(user=get_pk.user_pk)
            return redirect('request')

    else:
        forms = Request_Forms()
        context = {'forms': forms, 'get_pk': get_pk}
        return render(request, 'create_request.html', context)


def list_user_request(request, pk=None):
    if not request.user.is_authenticated:
        return redirect('login')
    get_pk = get_object_or_404(User, pk=pk)
    role = request.user.permit_user.get(user_permit_id=get_pk).role_permit
    print(role)
    if request.user.permit_user.filter(role_permit__role='User'):
        if user_request_table.objects.filter(user_request_id=get_pk) is not None:
            request_list = user_request_table.objects. \
                filter(user_request_id=get_pk).order_by('request_request__request_open')
            paginator = Paginator(request_list, 8)
            page_number = request.GET.get('page')
            try:
                pagy = paginator.get_page(page_number)
            except PageNotAnInteger:
                pagy = paginator.page(1)
            except EmptyPage:
                pagy = paginator.page(paginator.num_pages)
            context = {'get_pk': get_pk, 'pagy': pagy, 'role': role}
            return render(request, 'list_user_requests.html', context)
        else:
            pagy = 'No Requests'
        context = {'pagy': pagy}
    # query for admin and it team view
    elif request.user.permit_user.filter(role_permit__role='Admin').only() or request.user.permit_user.filter(role_permit__role='IT team').only():
        if user_request_table.objects.all() is not None:
            request_list = user_request_table.objects.all().order_by('request_request__request_open')
            paginator = Paginator(request_list, 8)
            page_number = request.GET.get('page')
            try:
                pagy = paginator.get_page(page_number)
            except PageNotAnInteger:
                pagy = paginator.page(1)
            except EmptyPage:
                pagy = paginator.page(paginator.num_pages)
            context = {'get_pk': get_pk, 'pagy': pagy, 'role': role}
            return render(request, 'list_user_requests.html', context)
        else:
            pagy = 'No Requests'
            context = {'pagy': pagy}
        return render(request, 'list_user_requests.html', context)
    return render(request, 'list_user_requests.html')


def assign_task(request, pk=None):
    if not request.user.is_authenticated:
        return redirect('login')
    get_pk = user_request_table.objects.get(pk=pk)
    if request.method == 'POST':
        assign = Assign_Forms(request.POST)
        if assign.is_valid():
            post = assign.save(commit=False)
            request_table.objects.filter(id=get_pk.request_request.pk). \
                update(assigned_to=post.assigned_to,
                       copy_team=post.copy_team, close_request=post.close_request)
            # invalidate the model request table not suitable for multiples database calls
            # try to invalidate object should work
            invalidate_model(request_table)
            messages.success(request, 'Request has been updated')
            logging_info_task(msg='Task has been assigned')
            return redirect('request')
    else:
        forms = Request_Forms(instance=get_pk.request_request)
        assign = Assign_Forms(request.POST)
        query = request_table.objects.get(id=get_pk.request_request.pk)
        context = {'forms': forms, 'assign': assign, 'query': query}
        return render(request, 'assign_task.html', context)
