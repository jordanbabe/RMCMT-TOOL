from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from django import forms
from .models import User


class CustomUserCreationForm(UserCreationForm):

    class Meta:
        model = User
        fields = ["first_name", "last_name", "email", "password1", "password2"]


class CustomUserChangeForm(UserChangeForm):

    class Meta:
        model = User
        fields = ["first_name", "last_name", "email"]


class LoginForm(forms.Form):
    email = forms.EmailField()
    password = forms.CharField(widget=forms.PasswordInput)