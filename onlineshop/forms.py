# coding=utf-8
from django.forms import ModelForm
from django import forms
from django.conf import settings
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from users.models import *

import re


class UserFirstLoginForm(forms.ModelForm):
    
    class Meta:

        model = User
        fields = ('email', 'password')