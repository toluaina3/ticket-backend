from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.forms import forms
from .models import User
from request.models import roles_table, bio


class Bio_Form(forms.ModelForm):
    class Meta:
        model = bio
        exclude = ['bio_user', 'bio_id']



class RegisterForms(UserCreationForm):
    first_name = forms.CharField(max_length=30)
    last_name = forms.CharField(max_length=30)
    email = forms.EmailField(max_length=20)
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
