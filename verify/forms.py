from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.forms import forms
from .models import User
from request.models import roles_table, bio, request_table, sla, priority_tables, response_table
from django.db.models.query_utils import Q
from cacheops import invalidate_model


class Response_Form(forms.ModelForm):
    class Meta:
        model = response_table
        exclude = ['time_response', 'time_response_update']


class Priority_Form(forms.ModelForm):
    class Meta:
        model = priority_tables
        exclude = ['priority_pk']


class Email_Requester(forms.Form):
    subject = forms.CharField(max_length=50, required=False)
    email = forms.CharField(max_length=2000, required=True, widget=forms.Textarea)


class Sla_request_Form(forms.ModelForm):
    invalidate_model(sla)
    choice = [(sla.sla_category, sla.sla_category) for sla in (sla.objects.all().order_by('sla_category').only())]
    sla_category = forms.ChoiceField(choices=choice, required=True, label='Category')

    class Meta:
        model = sla
        fields = ['sla_category']


class Sla_Form(forms.ModelForm):
    class Meta:
        model = sla
        fields = ['sla_time', 'sla_category']


class Assign_Forms(forms.ModelForm):
    # get the it team from query into the choice field
    invalidate_model(roles_table)
    choices = [(user.first_name + ' ' + user.last_name, user.get_full_name)
               for user in
               (User.objects.filter(Q(permit_user__role_permit__role='IT team')).order_by('first_name').only())]
    choices.insert(0, ('', 'None'))
    assigned_to = forms.ChoiceField(choices=choices, required=False)
    copy_team = forms.ChoiceField(choices=choices, required=False)

    class Meta:
        model = request_table
        fields = ['assigned_to', 'copy_team', 'close_request']


class Request_Forms(forms.ModelForm):
    class Meta:
        model = request_table
        exclude = ['request_time_closed', 'request_open', 'confirm', 'sla_category',
                   'request_time_update', 'request_time_started', 'ticket_number']


class Bio_Form(forms.ModelForm):
    class Meta:
        model = bio
        exclude = ['bio_user', 'bio_id']


class RegisterForms(UserCreationForm):
    first_name = forms.CharField(max_length=30)
    last_name = forms.CharField(max_length=30)
    email = forms.EmailField(max_length=40)
    IT = forms.BooleanField

    def __init__(self, *args, **kwargs):
        super(UserCreationForm, self).__init__(*args, **kwargs)

        for field in ['email', 'password1', 'password2']:
            self.fields[field].help_text = None

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'password1', 'password2']
        help_texts = {'is_staff': None}


class RoleForm(forms.ModelForm):
    class Meta:
        model = roles_table
        fields = ['role']


class UpdateBioForms(forms.ModelForm):
    class Meta:
        model = bio
        exclude = ['bio_user', 'bio_id', 'phone']
