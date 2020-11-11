from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from request.models import bio, permission, roles_table, user_request_table, request_table
from verify.models import User
from .forms import RegisterForms, RoleForm, Bio_Form
from django.db import transaction, IntegrityError
from cacheops import cached_view
from django.contrib.auth.forms import PasswordResetForm
from clean_code.tasks import send_mail_password_reset
from django.db.models import Count
from .forms import Assign_Forms
from django.db.models import Q


# Create your views here.
def login_view(request):
    # test for cookies on browser
    request.session.set_test_cookie()
    if request.session.test_cookie_worked():
        request.session.delete_test_cookie()
        response = 'Site with Cookies'
    else:
        response = 'Cookies not supported by your browser'
    context = {'response': response}
    # handles the login logic
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']
        user = authenticate(request, username=email, password=password)
        if email and user is not None:
            if user.is_active:
                login(request, user)
                return redirect('home')
            else:
                messages.error(request, 'User not active')
                return redirect(request, 'login')
        elif email and not user:
            messages.error(request, 'Failed Login, contact IT')
            return redirect('login')
        else:
            messages.error(request, '...Invalid Login...')
            # return to home page
            return redirect('login')
    return render(request, 'index.html', context)


def login_home(request):
    # global variables
    global request_open, request_closed, \
        request_completed, request_cancelled, \
        request_software, request_network, \
        request_authentication, request_email, \
        request_phone, request_printer, request_location_abuja, \
        request_location_ikoyi, request_location_lagos, \
        request_location_ph

    # variables for date range picker
    date = request.GET.get('daterange')
    date_parse = str(date).replace('/', '-')
    ren = date_parse[:10]
    den = date_parse[13:]
    team = request.GET.get('team-member')
    permission_query = permission.objects.get(user_permit_id=request.user.pk).role_permit.role
    # reporting for admin view
    if permission_query == 'Admin' and not None:
        # if range input is true to get status of request
        if date:
            request_status_query = user_request_table.objects.filter(request_request__request_open__range=[ren, den]) \
                .values('request_request__close_request'). \
                annotate(count_request_status=Count('request_request__close_request'))

            # function to search for key values in queries
            def search_filler(value, dictionary):
                for key in dictionary:
                    if key['request_request__close_request'] == value:
                        return key

            if search_filler('Open', request_status_query):
                dell = search_filler('Open', request_status_query)
                request_open = dell['count_request_status']
            elif search_filler('Open', request_status_query) is None:
                request_open = 0

            if search_filler('Closed', request_status_query):
                dell = search_filler('Closed', request_status_query)
                request_closed = dell['count_request_status']
            elif search_filler('Closed', request_status_query) is None:
                request_closed = 0

            if search_filler('Completed', request_status_query):
                dell = search_filler('Completed', request_status_query)
                request_completed = dell['count_request_status']
            elif search_filler('Completed', request_status_query) is None:
                request_completed = 0

            if search_filler('Cancelled', request_status_query):
                dell = search_filler('Cancelled', request_status_query)
                request_cancelled = dell['count_request_status']
            elif search_filler('Cancelled', request_status_query) is None:
                request_cancelled = 0
                # query the team member, if date is null
        if team and date:
            query_no_date = user_request_table.objects.filter(
                Q(request_request__assigned_to=team) & Q(request_request__request_open__range=[ren, den])) \
                    .values('request_request__close_request') \
                    .annotate(count_request_status=Count('request_request__close_request'))

            def search_filler(value, dictionary):
                for key in dictionary:
                    if key['request_request__close_request'] == value:
                        return key

            if search_filler('Open', query_no_date):
                dell = search_filler('Open', query_no_date)
                request_open = dell['count_request_status']
            elif search_filler('Open', query_no_date) is None:
                    request_open = 0

            if search_filler('Closed', query_no_date):
                    dell = search_filler('Closed', query_no_date)
                    request_closed = dell['count_request_status']
            elif search_filler('Closed', query_no_date) is None:
                    request_closed = 0

            if search_filler('Completed', query_no_date):
                    dell = search_filler('Completed', query_no_date)
                    request_completed = dell['count_request_status']
            elif search_filler('Completed', query_no_date) is None:
                    request_completed = 0

            if search_filler('Cancelled', query_no_date):
                    dell = search_filler('Cancelled', query_no_date)
                    request_cancelled = dell['count_request_status']
            elif search_filler('Cancelled', query_no_date) is None:
                    request_cancelled = 0

        # if the date range is not called, return the reports of request to the admin
        elif date is None:
            query_no_date = user_request_table.objects.values('request_request__close_request') \
                .annotate(count_request_status=Count('request_request__close_request'))

            def search_filler(value, dictionary):
                for key in dictionary:
                    if key['request_request__close_request'] == value:
                        return key

            if search_filler('Open', query_no_date):
                dell = search_filler('Open', query_no_date)
                request_open = dell['count_request_status']
            elif search_filler('Open', query_no_date) is None:
                request_open = 0

            if search_filler('Closed', query_no_date):
                dell = search_filler('Closed', query_no_date)
                request_closed = dell['count_request_status']
            elif search_filler('Closed', query_no_date) is None:
                request_closed = 0

            if search_filler('Completed', query_no_date):
                dell = search_filler('Completed', query_no_date)
                request_completed = dell['count_request_status']
            elif search_filler('Completed', query_no_date) is None:
                request_completed = 0

            if search_filler('Cancelled', query_no_date):
                dell = search_filler('Cancelled', query_no_date)
                request_cancelled = dell['count_request_status']
            elif search_filler('Cancelled', query_no_date) is None:
                request_cancelled = 0

        # report for request per category

        date_category = request.GET.get('date')
        date_parse_category = str(date_category).replace('/', '-')
        ren_category = date_parse_category[:10]
        den_category = date_parse_category[13:]
        if date_category is None:
            query_no_date = user_request_table.objects.values('request_request__sla_category__sla_category') \
                .annotate(count_request_category=Count('request_request__sla_category__sla_category'))

            def search_filler(value, dictionary):
                for key in dictionary:
                    if key['request_request__sla_category__sla_category'] == value:
                        return key

            if search_filler('Email', query_no_date):
                dell = search_filler('Email', query_no_date)
                request_email = dell['count_request_category']
            elif search_filler('Email', query_no_date) is None:
                request_email = 0

            if search_filler('Authentication', query_no_date):
                dell = search_filler('Authentication', query_no_date)
                request_authentication = dell['count_request_category']
            elif search_filler('Authentication', query_no_date) is None:
                request_authentication = 0

            if search_filler('Network', query_no_date):
                dell = search_filler('Network', query_no_date)
                request_network = dell['count_request_category']
            elif search_filler('Network', query_no_date) is None:
                request_network = 0

            if search_filler('Software', query_no_date):
                dell = search_filler('Software', query_no_date)
                request_software = dell['count_request_category']
            elif search_filler('Software', query_no_date) is None:
                request_software = 0

            if search_filler('Printer', query_no_date):
                dell = search_filler('Printer', query_no_date)
                request_printer = dell['count_request_category']
            elif search_filler('Printer', query_no_date) is None:
                request_printer = 0

            if search_filler('IP Phone', query_no_date):
                dell = search_filler('IP Phone', query_no_date)
                request_phone = dell['count_request_category']
            elif search_filler('IP Phone', query_no_date) is None:
                request_phone = 0

        # request category if the date is entered

        elif date_category:
            query_no_date = user_request_table.objects.filter \
                (request_request__request_open__range=[ren_category, den_category]) \
                .values('request_request__sla_category__sla_category') \
                .annotate(count_request_category=Count('request_request__sla_category__sla_category'))

            def search_filler(value, dictionary):
                for key in dictionary:
                    if key['request_request__sla_category__sla_category'] == value:
                        return key

            if search_filler('Email', query_no_date):
                dell = search_filler('Email', query_no_date)
                request_email = dell['count_request_category']
            elif search_filler('Email', query_no_date) is None:
                request_email = 0

            if search_filler('Authentication', query_no_date):
                dell = search_filler('Authentication', query_no_date)
                request_authentication = dell['count_request_category']
            elif search_filler('Authentication', query_no_date) is None:
                request_authentication = 0

            if search_filler('Network', query_no_date):
                dell = search_filler('Network', query_no_date)
                request_network = dell['count_request_category']
            elif search_filler('Network', query_no_date) is None:
                request_network = 0

            if search_filler('Software', query_no_date):
                dell = search_filler('Software', query_no_date)
                request_software = dell['count_request_category']
            elif search_filler('Software', query_no_date) is None:
                request_software = 0

            if search_filler('Printer', query_no_date):
                dell = search_filler('Printer', query_no_date)
                request_printer = dell['count_request_category']
            elif search_filler('Printer', query_no_date) is None:
                request_printer = 0

            if search_filler('IP Phone', query_no_date):
                dell = search_filler('IP Phone', query_no_date)
                request_phone = dell['count_request_category']
            elif search_filler('IP Phone', query_no_date) is None:
                request_phone = 0
        # total number of requests per regions
        query_requests_regions = User.objects.values('bio_user_relation__branch') \
            .annotate(count_request_location=Count('bio_user_relation__branch'))
        if query_requests_regions is not None:

            def search_filler(value, dictionary):
                for key in dictionary:
                    if key['bio_user_relation__branch'] == value:
                        return key

            if search_filler('Abuja', query_requests_regions):
                dell = search_filler('Abuja', query_requests_regions)
                request_location_abuja = dell['count_request_location']
            elif search_filler('Abuja', query_requests_regions) is None:
                request_location_abuja = 0

            if search_filler('Lagos', query_requests_regions):
                dell = search_filler('Lagos', query_requests_regions)
                request_location_lagos = dell['count_request_location']
            elif search_filler('Lagos', query_requests_regions) is None:
                request_location_lagos = 0

            if search_filler('Ikoyi', query_requests_regions):
                dell = search_filler('Ikoyi', query_requests_regions)
                request_location_ikoyi = dell['count_request_location']
            elif search_filler('Ikoyi', query_requests_regions) is None:
                request_location_ikoyi = 0

            if search_filler('Port-Harcourt', query_requests_regions):
                dell = search_filler('Port-Harcourt', query_requests_regions)
                request_location_ph = dell['count_request_location']
            elif search_filler('Port-Harcourt', query_requests_regions) is None:
                request_location_ph = 0
        else:
            pass

    # view for the users
    elif permission_query == 'User' and not None:
        user_query = user_request_table.objects.filter(user_request_id=request.user.pk)
        date = request.GET.get('daterange')
        date_parse = str(date).replace('/', '-')
        ren = date_parse[:10]
        den = date_parse[13:]
        # reporting for admin view
        if not date:
            request_status_query = user_query.values('request_request__close_request') \
                .values('request_request__close_request'). \
                annotate(count_request_status=Count('request_request__close_request'))

            # function to search for key values in queries
            def search_filler(value, dictionary):
                for key in dictionary:
                    if key['request_request__close_request'] == value:
                        return key

            if search_filler('Open', request_status_query):
                dell = search_filler('Open', request_status_query)
                request_open = dell['count_request_status']
            elif search_filler('Open', request_status_query) is None:
                request_open = 0

            if search_filler('Closed', request_status_query):
                dell = search_filler('Closed', request_status_query)
                request_closed = dell['count_request_status']
            elif search_filler('Closed', request_status_query) is None:
                request_closed = 0

            if search_filler('Completed', request_status_query):
                dell = search_filler('Completed', request_status_query)
                request_completed = dell['count_request_status']
            elif search_filler('Completed', request_status_query) is None:
                request_completed = 0

            if search_filler('Cancelled', request_status_query):
                dell = search_filler('Cancelled', request_status_query)
                request_cancelled = dell['count_request_status']
            elif search_filler('Cancelled', request_status_query) is None:
                request_cancelled = 0
        elif date:
            request_status_query = user_query.filter(request_request__request_open__range=[ren, den]) \
                .values('request_request__close_request') \
                .values('request_request__close_request'). \
                annotate(count_request_status=Count('request_request__close_request'))

            # function to search for key values in queries
            def search_filler(value, dictionary):
                for key in dictionary:
                    if key['request_request__close_request'] == value:
                        return key

            if search_filler('Open', request_status_query):
                dell = search_filler('Open', request_status_query)
                request_open = dell['count_request_status']
            elif search_filler('Open', request_status_query) is None:
                request_open = 0

            if search_filler('Closed', request_status_query):
                dell = search_filler('Closed', request_status_query)
                request_closed = dell['count_request_status']
            elif search_filler('Closed', request_status_query) is None:
                request_closed = 0

            if search_filler('Completed', request_status_query):
                dell = search_filler('Completed', request_status_query)
                request_completed = dell['count_request_status']
            elif search_filler('Completed', request_status_query) is None:
                request_completed = 0

            if search_filler('Cancelled', request_status_query):
                dell = search_filler('Cancelled', request_status_query)
                request_cancelled = dell['count_request_status']
            elif search_filler('Cancelled', request_status_query) is None:
                request_cancelled = 0

        date_category = request.GET.get('date')
        date_parse_category = str(date_category).replace('/', '-')
        ren_category = date_parse_category[:10]
        den_category = date_parse_category[13:]
        # view request per service
        if date_category is None:
            query_user_service = user_request_table.objects.filter(user_request_id=request.user.pk)
            query_no_date = query_user_service.values('request_request__sla_category__sla_category') \
                .annotate(count_request_category=Count('request_request__sla_category__sla_category'))

            def search_filler(value, dictionary):
                for key in dictionary:
                    if key['request_request__sla_category__sla_category'] == value:
                        return key

            if search_filler('Email', query_no_date):
                dell = search_filler('Email', query_no_date)
                request_email = dell['count_request_category']
            elif search_filler('Email', query_no_date) is None:
                request_email = 0

            if search_filler('Authentication', query_no_date):
                dell = search_filler('Authentication', query_no_date)
                request_authentication = dell['count_request_category']
            elif search_filler('Authentication', query_no_date) is None:
                request_authentication = 0

            if search_filler('Network', query_no_date):
                dell = search_filler('Network', query_no_date)
                request_network = dell['count_request_category']
            elif search_filler('Network', query_no_date) is None:
                request_network = 0

            if search_filler('Software', query_no_date):
                dell = search_filler('Software', query_no_date)
                request_software = dell['count_request_category']
            elif search_filler('Software', query_no_date) is None:
                request_software = 0

            if search_filler('Printer', query_no_date):
                dell = search_filler('Printer', query_no_date)
                request_printer = dell['count_request_category']
            elif search_filler('Printer', query_no_date) is None:
                request_printer = 0

            if search_filler('IP Phone', query_no_date):
                dell = search_filler('IP Phone', query_no_date)
                request_phone = dell['count_request_category']
            elif search_filler('IP Phone', query_no_date) is None:
                request_phone = 0
        elif date_category:
            query_user_service = user_request_table.objects.filter(user_request_id=request.user.pk)
            query_no_date = query_user_service.filter(request_request__request_open__range=[ren_category, den_category]) \
                .values('request_request__sla_category__sla_category') \
                .annotate(count_request_category=Count('request_request__sla_category__sla_category'))

            def search_filler(value, dictionary):
                for key in dictionary:
                    if key['request_request__sla_category__sla_category'] == value:
                        return key

            if search_filler('Email', query_no_date):
                dell = search_filler('Email', query_no_date)
                request_email = dell['count_request_category']
            elif search_filler('Email', query_no_date) is None:
                request_email = 0

            if search_filler('Authentication', query_no_date):
                dell = search_filler('Authentication', query_no_date)
                request_authentication = dell['count_request_category']
            elif search_filler('Authentication', query_no_date) is None:
                request_authentication = 0

            if search_filler('Network', query_no_date):
                dell = search_filler('Network', query_no_date)
                request_network = dell['count_request_category']
            elif search_filler('Network', query_no_date) is None:
                request_network = 0

            if search_filler('Software', query_no_date):
                dell = search_filler('Software', query_no_date)
                request_software = dell['count_request_category']
            elif search_filler('Software', query_no_date) is None:
                request_software = 0

            if search_filler('Printer', query_no_date):
                dell = search_filler('Printer', query_no_date)
                request_printer = dell['count_request_category']
            elif search_filler('Printer', query_no_date) is None:
                request_printer = 0

            if search_filler('IP Phone', query_no_date):
                dell = search_filler('IP Phone', query_no_date)
                request_phone = dell['count_request_category']
            elif search_filler('IP Phone', query_no_date) is None:
                request_phone = 0

        # request per region view not applicable to user
        request_location_abuja = 0
        request_location_ph = 0
        request_location_lagos = 0
        request_location_ikoyi = 0

    # return only database value, for database optimization
    if bio.objects.filter(bio_user=request.user.pk):
        qs = bio.objects.get(bio_user=request.user.pk).department
        # db attribute that are not callable is cached
        role = qs
    else:
        role = 'No role Assigned'
    user = request.user.get_full_name()
    context = {'role': role, 'user': user, 'request_open': request_open,
               'request_closed': request_closed,
               'request_completed': request_completed,
               'request_cancelled': request_cancelled,
               'request_email': request_email,
               'request_authentication': request_authentication,
               'request_software': request_software,
               'request_network': request_network,
               'request_printer': request_printer,
               'request_phone': request_phone, 'request_location_abuja': request_location_abuja,
               'request_location_ikoyi': request_location_ikoyi,
               'request_location_lagos': request_location_lagos,
               'request_location_ph': request_location_ph,
               'permission_query': permission_query}
    return render(request, 'home_login.html', context)


def log_out(request):
    logout(request)
    # delete the session when logged out
    del request.session
    return redirect('login')


@transaction.atomic
@cached_view(timeout=20)
def register_user(request):
    if request.method == 'POST':
        user_form = RegisterForms(request.POST)
        role_form = RoleForm(request.POST)
        bio_form = Bio_Form(request.POST)
        user_valid = user_form.is_valid()
        role_valid = role_form.is_valid()
        bio_valid = bio_form.is_valid()
        if user_valid and role_valid and bio_valid:
            with transaction.atomic():
                try:
                    post = user_form.save(commit=False)
                    beat = bio_form.save(commit=False)
                    get_form = (role_form.data['role'])
                    post.save()
                    # check if user exists in database
                    role_get = roles_table.objects.get(role=get_form)
                    # save role information if user information has been saved
                    bio.objects.create(branch=beat.branch, department=beat.department,
                                       phone=beat.phone, bio_user_id=post.pk)
                    permission.objects.create(user_permit_id=post.pk, role_permit_id=role_get.role_id)
                    messages.success(request, '{}, was successfully registered'.
                                     format(post.first_name + ' ' + post.last_name))
                    # redirect to login page
                    return redirect('login')
                    # condition for user exists in database
                    # else:
                    # messages.error(request, 'User exists')
                except ConnectionError:
                    messages.error(request, 'Database return Error')
    else:
        user_form = RegisterForms()
        role_form = RoleForm()
        bio_form = Bio_Form()
    context = {'user_form': user_form, 'role': role_form, 'bio_context': bio_form}
    return render(request, 'register.html', context)


def password_reset_request(request):
    if request.method == "POST":
        password_reset_form = PasswordResetForm(request.POST)
        if password_reset_form.is_valid():
            data = password_reset_form.cleaned_data['email']
            associated_users = User.objects.filter(Q(email=data))
            if associated_users.exists():
                for user in associated_users:
                    if user.is_superuser:
                        messages.error(request, 'This user can not receive password by email')
                        return redirect('login')
                    elif not user.is_active:
                        messages.error(request, 'User not active')
                        return redirect('login')
                    else:
                        # celery task to send email to user for password reset
                        send_mail_password_reset(user=user.pk)
                        return redirect("/password_reset/done/")
            messages.error(request, 'Account does not exist.')
    password_reset_form = PasswordResetForm()
    return render(request=request, template_name="password/password_reset.html",
                  context={"password_reset_form": password_reset_form})
