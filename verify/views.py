from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from request.models import bio, permission, roles_table
from verify.models import User
from .forms import RegisterForms, RoleForm, Bio_Form
from django.db import transaction, IntegrityError
from cacheops import cached_view
from django.contrib.auth.forms import PasswordResetForm
from django.db.models.query_utils import Q
from clean_code.tasks import send_mail_password_reset


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


# @cached_view(timeout=120)
def login_home(request):
    # return only database value, for database optimization
    if bio.objects.filter(bio_user=request.user.id):
        qs = bio.objects.get(bio_user=request.user.id).department
        # db attribute that are not callable is cached
        role = qs
    else:
        role = 'No role Assigned'
    user = request.user.get_full_name()
    context = {'role': role, 'user': user}
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
                                       phone=beat.phone, bio_user_id=post.id)
                    permission.objects.create(user_permit_id=post.id, role_permit_id=role_get.role_id)
                    # bio.objects.create(branch=beat.branch, department=beat.department,
                    # phone=beat.phone, job_title=beat.job_title, bio_user_id=post.id)
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
                        send_mail_password_reset(user=user.id)
                        return redirect("/password_reset/done/")
            messages.error(request, 'Account does not exist.')
    password_reset_form = PasswordResetForm()
    return render(request=request, template_name="password/password_reset.html",
                  context={"password_reset_form": password_reset_form})
