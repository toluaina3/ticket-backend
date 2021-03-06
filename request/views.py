from django.shortcuts import render, redirect, get_object_or_404, reverse
from verify.models import User
from request.models import permission
from django.views.generic.list import ListView
from verify.forms import UpdateBioForms, RoleForm
from .models import bio, roles_table, user_request_table, request_table, sla, priority_tables, response_table, \
    ticket_message_table
from django.contrib import messages
from django.db import transaction
from verify.forms import Request_Forms, Assign_Forms, RegisterForms, Sla_Form, \
    Sla_request_Form, Response_Form, Priority_Form
from cacheops import invalidate_model
from clean_code.tasks import send_mail_request_raised, \
    send_mail_request_raised_it_team, logging_info_task, send_mail_task_assigned_user, send_mail_task_completed_user, \
    send_mail_task_closed_user, send_mail_task_cancelled_request, \
    send_mail_task_response_requester, send_mail_task_assigned_started
from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage
from django.utils import timezone
from django.db.models import Q
from django.http import HttpResponseRedirect
from request.ticket_number import ticket_number


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
        first_name = request.POST['first_name']
        last_name = request.POST['last_name']
        email = request.POST['email']
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
                    bio.objects.filter(Q(bio_user_id=get_pk)).update(branch=post_three.branch,
                                                                     department=post_three.department)
                    permission.objects.filter(Q(user_permit_id=get_pk)).update(role_permit_id=get_role.pk)
                    # update the user's info
                    User.objects.filter(user_pk=get_pk.user_pk).update(first_name=first_name, last_name=last_name,
                                                                       email=email)
                    messages.success(request, '{}, was successfully Updated'.
                                     format(get_pk.first_name + ' ' + get_pk.last_name))
                    # invalidate the model tables
                    invalidate_model(bio)
                    invalidate_model(roles_table)
                    invalidate_model(User)
                    return redirect('user-management')
                except ConnectionError:
                    messages.error(request, 'Database Error')
        else:
            messages.error(request, 'User info can not update')
            return redirect('user-management')
    else:
        form_two = RoleForm(instance=roles_table.objects.get(permit_user_role__user_permit_id=get_pk))
        form_three = UpdateBioForms(instance=get_pk.bio_user_relation)
        user_form = RegisterForms(instance=get_pk)
        context = {'form_two': form_two, 'form_three': form_three, 'get_pk': get_pk, 'user_form': user_form}
        return render(request, 'update_user_management.html', context=context)


def deactivate_user(request, pk=None):
    if not request.user.is_authenticated:
        return redirect('user-management')
    get_pk = get_object_or_404(User, pk=pk)
    if request.method == 'POST' or 'GET':
        if User.objects.get(email__exact=get_pk.email).is_active is True and not None:
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
    global overdue_request
    if request.method == 'POST':
        forms = Request_Forms(request.POST)
        sla_category = Sla_request_Form(request.POST).data['sla_category']
        print(forms.errors)
        if forms.is_valid():
            post = forms.save(commit=False)
            get_category = sla.objects.get(sla_category=sla_category)
            request_add = request_table.objects.create(request=post.request, sla_category=get_category,
                                                       ticket_number=ticket_number())
            user_request_table.objects.create(user_request_id=get_pk.user_pk, request_request_id=request_add.pk)
            messages.success(request, 'Request has been Submitted')
            # task of logged message
            logging_info_task(msg='Request raised for the user {}'.format(request.user.get_full_name))
            # send acknowledgment mail to user when request has been raised
            send_mail_request_raised(user=get_pk.user_pk)
            # send mail to the ticket@team when request is raised
            send_mail_request_raised_it_team(user=get_pk.user_pk)
            return redirect('request')
        else:
            messages.error(request, 'Form is invalid')
            return HttpResponseRedirect(reverse('request-list', args=[get_pk.user_pk]))
    else:
        forms = Request_Forms()
        sla_category = Sla_request_Form()
        context = {'forms': forms, 'get_pk': get_pk, 'sla_category': sla_category}
        return render(request, 'create_request.html', context)


def list_user_request(request, pk=None):
    global overdue_request
    if not request.user.is_authenticated:
        return redirect('login')
    get_pk = get_object_or_404(User, pk=pk)
    role = request.user.permit_user.filter(user_permit_id=get_pk).values('role_permit__role')[0]['role_permit__role']
    if request.user.permit_user.filter(role_permit__role='User').only().cache():
        if user_request_table.objects.filter(user_request_id=get_pk) is not None:
            request_list = user_request_table.objects. \
                filter(user_request_id=get_pk).order_by('-request_request__request_open').only().cache()
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
    elif request.user.permit_user.filter(role_permit__role='Admin').only().cache():
        # color code the overdue request on the view table
        over = []
        if user_request_table.objects.all() is not None:
            request_list = user_request_table.objects.all().order_by('-request_request__request_open').only().cache()
            paginator = Paginator(request_list, 8)
            page_number = request.GET.get('page')
            try:
                pagy = paginator.get_page(page_number)
                # call the zip method to run for loop in parallel with request and overdue
                loop = zip(over, pagy)
                if pagy is not None:
                    for listing in pagy:
                        get_time = listing.request_request.request_open + \
                                   timezone.timedelta(minutes=listing.request_request.sla_category.sla_time)
                        # show the overdue request with color code on the view table

                        if timezone.now() > get_time and not None:
                            overdue_request = 'Yes'
                            over.append(overdue_request)
                        # show the request with color code on the view table
                        elif timezone.now() < get_time and not None:
                            overdue_request = 'No'
                            over.append(overdue_request)
                        else:
                            pass
                else:
                    pass
            except PageNotAnInteger:
                pagy = paginator.page(1)
            except EmptyPage:
                pagy = paginator.page(paginator.num_pages)
            context = {'get_pk': get_pk, 'pagy': pagy, 'role': role, 'loop': loop}
            messages.success(request, 'Welcome, Admin')
            return render(request, 'list_user_requests.html', context)
        else:
            pagy = 'No Requests'
            context = {'pagy': pagy}
        return render(request, 'list_user_requests.html', context)
    # view for IT team, only assigned task are seen.
    elif request.user.permit_user.filter(role_permit__role='IT team').only().cache():
        over = []
        if user_request_table.objects.filter(request_request__assigned_to=get_pk) is not None:
            request_list = user_request_table.objects.filter(
                request_request__assigned_to=get_pk.first_name + ' ' + get_pk.last_name) \
                .order_by('-request_request__request_open').only().cache()
            paginator = Paginator(request_list, 8)
            page_number = request.GET.get('page')
            try:
                pagy = paginator.get_page(page_number)
                loop = zip(over, pagy)
                if pagy is not None:
                    for listing in pagy:
                        get_time = listing.request_request.request_open + \
                                   timezone.timedelta(minutes=listing.request_request.sla_category.sla_time)
                        # show the overdue request with color code on the view table

                        if timezone.now() > get_time and not None:
                            overdue_request = 'Yes'
                            over.append(overdue_request)
                        # show the request with color code on the view table
                        elif timezone.now() < get_time and not None:
                            overdue_request = 'No'
                            over.append(overdue_request)
                        else:
                            pass
                else:
                    pass
            except PageNotAnInteger:
                pagy = paginator.page(1)
            except EmptyPage:
                pagy = paginator.page(paginator.num_pages)
            context = {'get_pk': get_pk, 'pagy': pagy, 'role': role, 'loop': loop}
            return render(request, 'list_user_requests.html', context)
    messages.error(request, 'Role has not been assigned')
    return render(request, 'list_user_requests.html', {'get_pk': get_pk})


def assign_task(request, pk=None):
    if not request.user.is_authenticated:
        return redirect('login')
    get_pk = user_request_table.objects.get(pk=pk)
    time = timezone.now()
    global due
    # display the due date for the request
    if get_pk is not None:
        get_time = get_pk.request_request.request_open + \
                   timezone.timedelta(minutes=get_pk.request_request.sla_category.sla_time)
        # show the overdue request with color code on the view table
        if timezone.now() > get_time and not None:
            due = get_time
        else:
            due = 'Within SLA time'
    if request.method == 'POST':
        assign = Assign_Forms(request.POST)
        if assign.is_valid():
            post = assign.save(commit=False)
            # request_table.objects.filter(id=get_pk.request_request.pk). \
            # update(assigned_to=post.assigned_to,
            # copy_team=post.copy_team, close_request=post.close_request)
            # if the request is completed by IT team, send a mail to user to click the confirm button
            # so the IT team can close the request
            if post.close_request == 'Completed':
                gold = request_table.objects.filter(id=get_pk.request_request.pk) \
                    .values('close_request')
                get_format = gold[0]['close_request']
                if get_format == 'Started':
                    request_table.objects.filter(id=get_pk.request_request.pk). \
                        update(close_request=post.close_request, request_time_closed=timezone.now())
                    send_mail_task_completed_user(user=get_pk.user_request.pk, assign=post.assigned_to)
                    # update the completed time field in the database
                    request_table.objects.filter(id=get_pk.request_request.pk).update(
                        request_time_closed=timezone.now())
                    messages.success(request, 'You completed the request')
                    # log to show date and time of task assigned to an IT staff
                    logging_info_task(msg='Task completed by  {}'.format(post.assigned_to))
                    invalidate_model(request_table)
                    return HttpResponseRedirect(reverse('assign-task', args=[get_pk.pk]))
                messages.error(request, '!! Invalid request, Only Stared tickets can be completed !!')
                return HttpResponseRedirect(reverse('assign-task', args=[get_pk.pk]))
            elif post.close_request == 'Cancelled':
                gold = request_table.objects.filter(id=get_pk.request_request.pk) \
                    .values('close_request')
                get_format = gold[0]['close_request']
                if get_format == 'Open' or get_format == 'Started':
                    request_table.objects.filter(id=get_pk.request_request.pk) \
                        .update(close_request='Cancelled', request_time_closed=timezone.now())
                    send_mail_task_cancelled_request(user=get_pk.user_request.pk)
                    messages.success(request, 'The request has been cancelled, user has been notified')
                    invalidate_model(request_table)
                    return HttpResponseRedirect(reverse('assign-task', args=[get_pk.pk]))
                messages.error(request, '!! Invalid request, Only Opened or Stared tickets can be cancelled !!')
                logging_info_task(msg='Ticket cancelled by  {}'.format(get_pk.user_request.pk))
                return HttpResponseRedirect(reverse('assign-task', args=[get_pk.pk]))
            elif post.close_request == 'Started':
                gold = request_table.objects.filter(id=get_pk.request_request.pk) \
                    .values('close_request')
                silver = request_table.objects.filter(id=get_pk.request_request.pk) \
                    .values('assigned_to')
                get_silver = silver[0]['assigned_to']
                get_format = gold[0]['close_request']
                if get_format == 'Open' and get_silver != 'None':
                    request_table.objects.filter(id=get_pk.request_request.pk) \
                        .update(close_request='Started', request_time_started=timezone.now(),
                                copy_team=post.copy_team)
                    send_mail_task_assigned_started(user=get_pk.user_request.pk, assign=post.assigned_to)
                    messages.success(request, 'Ticket started, user has been notified')
                    invalidate_model(request_table)
                    logging_info_task(msg='Ticket Started by  {}'.format(post.assigned_to))
                    return HttpResponseRedirect(reverse('assign-task', args=[get_pk.pk]))
                messages.error(request, '!! Invalid request, assigned open tickets can only be started !!')
                return HttpResponseRedirect(reverse('assign-task', args=[get_pk.pk]))
            # logic to close the request without user confirmation
            elif post.close_request == 'Closed':
                gold = request_table.objects.filter(id=get_pk.request_request.pk) \
                    .values('close_request')
                get_format = gold[0]['close_request']
                if get_format == 'Completed':
                    get_time_format = request_table.objects.filter(id=get_pk.request_request.pk) \
                        .values('request_time_closed')
                    get_time_completed = get_time_format[0]['request_time_closed']
                    hour_to_close = get_time_completed + timezone.timedelta(hours=24)
                    if timezone.now() > hour_to_close:
                        request_table.objects.filter(id=get_pk.request_request.pk) \
                            .update(close_request='Closed', request_time_closed=timezone.now())
                        invalidate_model(request_table)
                        messages.success(request, 'Ticket closed by the Support team')
                        logging_info_task(msg='Ticket Closed')
                        send_mail_task_closed_user(user=get_pk.user_request.pk)
                        return HttpResponseRedirect(reverse('assign-task', args=[get_pk.pk]))
                    else:
                        messages.error(request,
                                       '!! Ticket can be after closed 24 hours without customers confirmation !!')
                        return HttpResponseRedirect(reverse('assign-task', args=[get_pk.pk]))
                else:
                    messages.error(request, '!! Ticket must be completed before closure !!')
                    return HttpResponseRedirect(reverse('assign-task', args=[get_pk.pk]))
            else:
                # invalidate the model request table not suitable for multiples database calls
                # try to invalidate object should work
                invalidate_model(request_table)
                # send email to user and assignee when request has been assigned to a staff
                if post.assigned_to:
                    try:
                        get_team = User.objects.filter(Q(first_name=str(post.assigned_to.split(' ')[0]))
                                                       & Q(last_name=str(post.assigned_to.split(' ')[1])))
                        it_team_assigned_pk = get_team.values('user_pk')[0]['user_pk']
                        lead = [get_pk.user_request.pk, it_team_assigned_pk]
                        request_table.objects.filter(id=get_pk.request_request.pk). \
                            update(assigned_to=post.assigned_to,
                                   copy_team=post.copy_team, close_request=post.close_request)
                        for i in lead:
                            send_mail_task_assigned_user(user=i, assign=post.assigned_to)
                        # log to show date and time of task assigned to an IT staff
                        logging_info_task(msg='Task has been assigned to {}'.format(post.assigned_to))
                        messages.success(request, 'Request has been assigned to {}'.format(post.assigned_to))
                        # track the time tickets are assigned to the team
                        request_table.objects.filter(id=get_pk.request_request.pk). \
                            update(request_time_update=timezone.now())
                        invalidate_model(request_table)
                        logging_info_task(msg='Ticket assigned to {}'.format(post.assigned_to))
                        # fix error of user changing uuid
                        return HttpResponseRedirect(reverse('assign-task', args=[get_pk.pk]))
                    except IndexError:
                        messages.error(request, 'Invalid request operation')
                        # return HttpResponseRedirect(reverse('request-list', args=[get_pk.user_request.user_pk]))
            # if assign form is None, return message
            messages.error(request, '!! Assign the task to a team member !!')
            return HttpResponseRedirect(reverse('assign-task', args=[get_pk.pk]))
    else:
        forms = Request_Forms(instance=get_pk.request_request)
        query = request_table.objects.get(id=get_pk.request_request.pk)
        assign = Assign_Forms(instance=request_table.objects.get(id=get_pk.request_request.pk))
        assigned_time = ''
        context = {'forms': forms, 'assign': assign, 'query': query,
                   'get_pk': get_pk, 'due': due, 'time': time}
        return render(request, 'assign_task.html', context)


def user_confirm_request(request, pk=None):
    if not request.user.is_authenticated:
        return redirect('login')
    get_pk = request_table.objects.get(pk=pk)
    if request.method == 'POST' or 'GET':
        # user click confirm button, request updates to close
        if not request_table.objects.get(id=get_pk.pk).confirm:
            request_table.objects.filter(id=get_pk.pk) \
                .update(close_request='Closed', confirm='True', request_time_closed=timezone.now())
            # invalidate the request table
            invalidate_model(request_table)
            messages.success(request, 'Your request has been closed')
            # handled by celery task
            use = user_request_table.objects.get(request_request_id=get_pk.pk)
            logging_info_task(msg='Request closed for {}'.format(use.user_request.get_full_name))
            send_mail_task_closed_user(user=use.user_request.pk)
            return redirect('request')
        else:
            messages.error(request, 'User must confirm before closing the request')
            return redirect('request')


def sla_create(request):
    if not request.user.is_authenticated:
        return redirect('login')
    if request.method == 'POST':
        form = Sla_Form(request.POST)
        form2 = Priority_Form(request.POST)
        if form.is_valid() and form2.is_valid():
            post = form.save(commit=False)
            get_form = (form2.data['priority_field'])
            save_priority = priority_tables.objects.create(priority_field=get_form)
            if not sla.objects.filter(sla_category=post.sla_category):
                sla.objects.create(sla_category=post.sla_category,
                                   sla_time=post.sla_time, sla_priority_id=save_priority.pk)
                invalidate_model(sla)
                invalidate_model(priority_tables)
                messages.success(request, 'SLA has been updated')
                logging_info_task(msg='SLA created')
                return redirect('sla-view')
        # form will throw error of validation
        # statement starts from valid
        messages.error(request, 'SLA service exists')
        logging_info_task(msg='Error creating SLA due to existing record')
        return redirect('sla-create')
    query = sla.objects.all().order_by('sla_category')
    paginator = Paginator(query, 8)
    page_number = request.GET.get('page')
    try:
        pagy = paginator.get_page(page_number)
    except PageNotAnInteger:
        pagy = paginator.page(1)
    except EmptyPage:
        pagy = paginator.page(paginator.num_pages)
    form = Sla_Form()
    form2 = Priority_Form()
    context = {'form': form, 'pagy': pagy, 'form2': form2}
    return render(request, 'sla_create.html', context)


def sla_view(request):
    if not request.user.is_authenticated:
        return redirect('login')
    global query
    if sla.objects.all() is not None:
        query = sla.objects.all().order_by('sla_category').cache()
    elif sla.objects.all is None:
        messages.error(request, 'No service added')
    paginator = Paginator(query, 8)
    page_number = request.GET.get('page')
    try:
        pagy = paginator.get_page(page_number)
    except PageNotAnInteger:
        pagy = paginator.page(1)
    except EmptyPage:
        pagy = paginator.page(paginator.num_pages)
    context = {'query': query, 'pagy': pagy}
    return render(request, 'sla_view.html', context)


def sla_update(request, pk=None):
    if not request.user.is_authenticated:
        return redirect('login')
    get_pk = get_object_or_404(sla, pk=pk)
    if request.method == 'POST':
        sla_category = request.POST['sla_category']
        sla_time = request.POST['sla_time']
        priority_field = request.POST['priority_field']
        if sla.objects.filter(sla_category=sla_category):
            # if priority level has not been created, then create here
            if not priority_tables.objects.filter(priority_field=priority_field):
                key = priority_tables.objects.create(priority_field=priority_field)
                sla.objects.filter(id=get_pk.pk).update(sla_category=sla_category, sla_time=sla_time,
                                                        sla_priority_id=key)
                messages.success(request, 'SLA has been updated')
                invalidate_model(sla)
                logging_info_task(msg='SLA updated with Priority')
                invalidate_model(priority_tables)
                return redirect('sla-view')
            # if priority exists
            key = priority_tables.objects.get(priority_field=priority_field).pk
            sla.objects.filter(id=get_pk.pk).update(sla_category=sla_category, sla_time=sla_time, sla_priority_id=key)
            messages.success(request, 'SLA has been updated')
            invalidate_model(sla)
            invalidate_model(priority_tables)
            return redirect('sla-view')
        messages.error(request, 'Can not update service')
        logging_info_task(msg='SLA update error')
        return redirect('sla-view')
    query = sla.objects.all().order_by('sla_category')
    paginator = Paginator(query, 8)
    page_number = request.GET.get('page')
    try:
        pagy = paginator.get_page(page_number)
    except PageNotAnInteger:
        pagy = paginator.page(1)
    except EmptyPage:
        pagy = paginator.page(paginator.num_pages)
    form = Sla_Form(instance=get_pk)
    form2 = Priority_Form(instance=get_pk)
    context = {'form': form, 'pagy': pagy, 'form2': form2}
    return render(request, 'sla_update.html', context)


def sla_delete(request, pk=None):
    if not request.user.is_authenticated:
        return redirect('login')
    get_pk = get_object_or_404(sla, pk=pk)
    if request.method == 'POST' or 'GET':
        if sla.objects.filter(id=get_pk.pk) is not None:
            # delete the sla record
            sla.objects.get(id=get_pk.pk).delete()
            invalidate_model(sla)
            messages.success(request, 'Service has been deleted')
            return redirect('sla-view')
        else:
            messages.error(request, 'Your request can not be processed, contact Admin')
            return redirect('sla-view')
    messages.error(request, 'Can not POST request')
    return redirect('sla-view')


def search_request_list_query(request):
    if not request.user.is_authenticated:
        return redirect('login')
    # the search query
    search_field = request.GET.get('search')
    if str(search_field) is not None:
        query_search = user_request_table.objects.filter(Q(request_request__request__icontains=search_field) |
                                                         Q(request_request__request__exact=search_field)
                                                         | Q(user_request__first_name__icontains=search_field)
                                                         | Q(user_request__first_name__exact=search_field)
                                                         | Q(user_request__last_name__icontains=search_field)
                                                         | Q(user_request__last_name__exact=search_field)
                                                         | Q(request_request__assigned_to__icontains=search_field)
                                                         | Q(request_request__assigned_to__exact=search_field)
                                                         | Q(request_request__ticket_number__exact=search_field)
                                                         | Q(
            request_request__sla_category__sla_category__exact=search_field)
                                                         | Q(
            request_request__sla_category__sla_category__icontains=search_field)
                                                         | Q(request_request__close_request__icontains=search_field)) \
            .order_by('-request_request__request_open')
        paginator = Paginator(query_search, 8)
        page_number = request.GET.get('page')
        try:
            pagy = paginator.get_page(page_number)
        except PageNotAnInteger:
            pagy = paginator.page(1)
        except EmptyPage:
            pagy = paginator.page(paginator.num_pages)
        context = {'pagy': pagy}
        return render(request, 'search_request_query.html', context)
    messages.error(request, 'Data not found')
    return redirect('request-list')


def request_response(request, pk=None):
    if not request.user.is_authenticated:
        return redirect('login')
    get_pk = get_object_or_404(user_request_table, pk=pk)
    query = ticket_message_table.objects.filter(ticket_request_id=get_pk.request_request.pk) \
        .values('ticket_message__response', 'ticket_message__time_response').order_by('-ticket_message__time_response')
    list_query = []
    list_time_query = []
    packed = zip(list_query, list_time_query)
    if query is not None:
        for i in query:
            real_query = i['ticket_message__response']
            time_query = i['ticket_message__time_response']
            list_query.append(real_query)
            list_time_query.append(time_query)
    else:
        pass
    context = {'get_pk': get_pk, 'query': query, 'packed': packed}
    return render(request, 'request_response.html', context)


def compose_response(request, pk=None):
    if not request.user.is_authenticated:
        return redirect('login')
    get_pk = get_object_or_404(user_request_table, pk=pk)
    if request.method == 'POST':
        form = Response_Form(request.POST)
        if form.is_valid():
            post = form.save(commit=False)
            post.save()
            # get the date and time of the post
            response_table.objects.filter(id=post.id).update(time_response=timezone.now())
            ticket_message_table.objects.create(ticket_request_id=get_pk.request_request.pk, ticket_message_id=post.id)
            invalidate_model(ticket_message_table)
            return HttpResponseRedirect(reverse('ticket-message', args=[get_pk.pk]))
        else:
            pass
    form = Response_Form()
    context = {'form': form, 'get_pk': get_pk}
    return render(request, 'compose_response.html', context)


# from the ticket number, get the time logs for a request
def request_time_log(request, pk=None):
    if not request.user.is_authenticated:
        return redirect('login')
    get_pk = get_object_or_404(user_request_table, pk=pk)
    global query_time_closed, query_request, query_time_start, query_time_assigned, query_time_open, sla_time
    query = request_table.objects.filter(pk=get_pk.request_request.pk).values('request', 'request_time_update',
                                                                              'request_time_started',
                                                                              'request_time_closed', 'request_open',
                                                                              'sla_category__sla_time')
    for i in query:
        query_request = i['request']
        query_time_assigned = i['request_time_update']
        query_time_start = i['request_time_started']
        query_time_closed = i['request_time_closed']
        query_time_open = i['request_open']
        query_sla = i['sla_category__sla_time']
        get_overdue_time = query_time_open + timezone.timedelta(minutes=query_sla)
        # if the ticket time close is greater than the the time ticket open and sla time
        if query_time_closed is not None:
            if query_time_closed > get_overdue_time and not None:
                sla_time = 'Outside SLA'
            elif query_time_closed <= get_overdue_time and not None:
                sla_time = 'Within SLA'
            else:
                pass
        else:
            sla_time = 'Ongoing'

    context = {'query_time_closed': query_time_closed, 'query_request': query_request,
               'query_time_start': query_time_start, 'query_time_assigned': query_time_assigned,
               'query_time_open': query_time_open, 'sla_time': sla_time}
    return render(request, 'ticket_time_logs.html', context)
