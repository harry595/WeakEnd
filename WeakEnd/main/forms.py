from django.contrib.auth.models import User
from django import forms
from django.core.exceptions import ValidationError
from django.contrib.auth.forms import UserCreationForm
from .models import Profile


class UserForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'username','password')

class ProfileForm(forms.ModelForm):
    class Meta:
        model = Profile
        fields = ('job', 'age', 'gender','purpose')