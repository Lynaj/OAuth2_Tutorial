
# Installation
#### Setting up Virtualenv
[Documentation](https://virtualenv.pypa.io/en/stable/)
```
# Install Virtualenv
pip install virtualenv
# Create the virtual environment
virtualenv venv
# Activate it
# -- MAC/LINUX --
source venv/bin/activate 
# -- WINDOWS -- 
./venv/scripts/activate
# ----
# Install dependecies
pip install django social-auth-app-django
```

### Creating the server's template & adding completely new application:

```
python -m django startproject onlineshop
cd onlineshop
python manage.py startapp users
```

The final folder's structure should look like this:

# Configuration
```sh
-> src
  -> onlineshop
       __init__.py
       settings.py
       urls.py
       wsgi.py
   -> users
        __init__.py
        admin.py
        apps.py
        models.py
        tests.py
        views.py
    manage.py
-> venv
```

> settings.py allows us to easily setup and control the way back-end system works

###### onlineshop/settings.py
```sh
# --- Add the required apps

INSTALLED_APPS = [
    'django.contrib.admin',
    ...
    'social_django', # Instagram, Facebook, OAuth2 etc.
    'users', # Newly created application
]

SOCIAL_AUTH_AUTHENTICATION_BACKENDS = (
    'social_core.backends.instagram.InstagramOAuth2'
    'social_core.backends.facebook.FacebookOAuth2',
    'social_core.backends.open_id.OpenIdAuth',
    'social_core.backends.google.GoogleOpenId',
    'social_core.backends.google.GoogleOAuth2',
    'social_core.backends.google.GoogleOAuth'
)

AUTHENTICATION_BACKENDS = (
    'social_core.backends.instagram.InstagramOAuth2',
    'social_core.backends.facebook.FacebookOAuth2',
    'social_core.backends.open_id.OpenIdAuth',
    'social_core.backends.google.GoogleOpenId',
    'social_core.backends.google.GoogleOAuth2',
    'social_core.backends.google.GoogleOAuth',
    'django.contrib.auth.backends.ModelBackend'
)

'''
 LOGIN_URL, LOGOUT_URL, LOGIN_REDIRECT_URL are responsible for
 handling the user's requests when it bases on social-auth-app-django library
'''

LOGIN_URL = 'login'
LOGOUT_URL = 'logout'
LOGIN_REDIRECT_URL = 'home'


# The last step is about giving every single existing host a permission.
# this option is limited to development only

ALLOWED_HOSTS = ['*']
```
# Google Authentication

> In this section we will focuse on setting up the authentication via Google.


###### onlineshop/settings.py
```
SOCIAL_AUTH_GOOGLE_OAUTH_KEY = '<GOOGLE-oauth-key>' # App ID
SOCIAL_AUTH_GOOGLE_OAUTH_SECRET = '<GOOGLE-oauth-secret>' # App Secret
SOCIAL_AUTH_GOOGLE_SCOPE = ['email']
SOCIAL_AUTH_GOOGLE_PROFILE_EXTRA_PARAMS = {
  'fields': 'id, email'
}
SOCIAL_AUTH_GOOGLE_EXTRA_DATA = [
    ('email', 'email')
]
```




## Instagram Authentication

> In this section we will focuse on setting up the authentication via Instagram.

##### onlineshop/settings.py
```
SOCIAL_AUTH_INSTAGRAM_OAUTH_KEY = '<INSTAGRAM-oauth-key>' # App ID
SOCIAL_AUTH_INSTAGRAM_OAUTH_SECRET = '<INSTAGRAM-oauth-secret>' # App Secret
SOCIAL_AUTH_INSTAGRAM_SCOPE = ['email']
SOCIAL_AUTH_INSTAGRAM_PROFILE_EXTRA_PARAMS = {
  'fields': 'id, email'
}
SOCIAL_AUTH_INSTAGRAM_EXTRA_DATA = [
    ('email', 'email')
]
```

## Facebook Authentication

> In this section we will focuse on setting up the authentication via Facebook.

##### onlineshop/settings.py
```
SOCIAL_AUTH_FACEBOOK_OAUTH_KEY = '<FACEBOOK-oauth-key>' # App ID
SOCIAL_AUTH_FACEBOOK_OAUTH_SECRET = '<FACEBOOK-oauth-secret>' # App Secret
SOCIAL_AUTH_FACEBOOK_SCOPE = ['email']
SOCIAL_AUTH_FACEBOOK_PROFILE_EXTRA_PARAMS = {
  'fields': 'id, email'
}
SOCIAL_AUTH_FACEBOOK_EXTRA_DATA = [
    ('email', 'email')
]
```


# Custom User Model

In order to fully satisfy the need of authenticating the user, basing on his or her
e-mail addres, we do have to rewrite default implementation of the User model



##### users/models.py
```
from uuid import uuid4

from django.contrib.auth.models import BaseUserManager, AbstractBaseUser, PermissionsMixin
from django.db import models
from django.utils import timezone
from django.db.models.signals import post_save, pre_save, pre_delete, post_delete
from social_django.models import UserSocialAuth

import json

class UserManager(BaseUserManager):
    def _create_user(
            self,
            email,
            password,
            is_staff,
            is_superuser,
            **extra_fields):
        """
        Creates and saves a User with the given username, email and password.
        """
        user = self.model(email=self.normalize_email(email),
                          is_active=True,
                          is_staff=is_staff,
                          is_superuser=is_superuser,
                          last_login=timezone.now(),
                          registered_at=timezone.now(),
                          **extra_fields)

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email=None, password=None, **extra_fields):
        is_staff = extra_fields.pop('is_staff', False)
        is_superuser = extra_fields.pop('is_superuser', False)
        return self._create_user(
            email,
            password,
            is_staff,
            is_superuser,
            **extra_fields)

    def create_superuser(self, email, password, **extra_fields):
        return self._create_user(
            email,
            password,
            is_staff=True,
            is_superuser=True,
            **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(
        verbose_name='Email',
        unique=True,
        max_length=255)
    first_name = models.CharField(
        verbose_name='First name',
        max_length=30,
        default='first')
    last_name = models.CharField(
        verbose_name='Last name',
        max_length=30,
        default='last')
    token = models.CharField(
        verbose_name='Token',
        max_length=30,
        default=uuid4,
        editable=False
    )

    '''
    Indicated whether user has to change his/her email address
    or not
    '''
    email_validated = models.BooleanField(default=True)

    is_admin = models.BooleanField(verbose_name='Admin', default=False)
    is_active = models.BooleanField(verbose_name='Active', default=True)
    is_staff = models.BooleanField(verbose_name='Staff', default=False)
    registered_at = models.DateTimeField(
        verbose_name='Registered at',
        auto_now_add=timezone.now)

    active_at = models.DateTimeField(
        verbose_name='Active at',
        blank=True,
        auto_now_add=timezone.now
    )

    # Fields settings   
    '''
    Especially important line. Tells the system to actually
    anthenticate the user basing on his e-mail address
    '''
    EMAIL_FIELD = 'email'
    USERNAME_FIELD = 'email'

    objects = UserManager()

    class Meta:
        verbose_name = 'User'
        verbose_name_plural = 'Users'
```

The entire system is working directly with 3rd party library, called social-auth-app-django.
Unfortunately, it does not handle the creation of new User object as good, as it should.
To repair it's workflow, a simple trigger action has to be added: 

##### users/models.py
```
def CreateBasicUserObject(sender,
                        instance,
                        created,
                        raw,
                        using,
                        update_fields,
                        **kwargs):
    
    if(created):
        loaded_data = instance.extra_data
        try:
            if(len(loaded_data) > 0):

                if('email' not in loaded_data['user']):
                    email_validated_flag = False
                    # Mocking email address
                    loaded_email = loaded_data['user']['username'] + '@localhost.com'
                else:
                    email_validated_flag = True
                    loaded_email = loaded_data['user']['email']

                instance.user.email=loaded_email
                instance.user.token=loaded_data['access_token']
                instance.user.password=User.objects.make_random_password()
                instance.user.email_validated=email_validated_flag

                instance.user.save()

        except Exception as e:
            pass
    
post_save.connect(CreateBasicUserObject, sender=UserSocialAuth)
```
It ensures us, that each and every time a completely new UserSocialAuth object is being created,
automatically User object's linked to it is affeted, so that it's e-mail address get updated


Moreover, to make sure, that the application recognizes this configuration,
it is highly recommended to insert following lines into the file settings.py:

###### onlineshop/settings.py
```
AUTH_USER_MODEL = 'users.User'
SOCIAL_AUTH_USER_MODEL = 'users.User'
SOCIAL_AUTH_USERNAME_IS_FULL_EMAIL = True
SOCIAL_AUTH_POSTGRES_JSONFIELD = True
```
## Corresponding views


>home function, that is being shown below, is responsible for redirecting user if and only if
his e-mail address has not been properly imported from the social media. Otherwise, it renders
a template containing basic user's information
###### onlineshop/views.py
```
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, render, redirect
from .forms import *

@login_required
def home(request):

    if(request.user.email_validated == False):

        return redirect('change_email')

    return render(request, 'home.html')

```

>change_email function helps the user with changing the e-mail, as well as the password. 
It bases on a simple form validation

###### onlineshop/views.py
```
@login_required
def change_email(request):
    if(request.user.email_validated == True):
        return redirect('home')
    else:
        if request.method == 'POST':
                    
            form = UserFirstLoginForm(request.POST)

            if form.is_valid():

                request.user.email = form.cleaned_data.get('email')
                request.user.password = form.cleaned_data.get('password')
                request.user.email_validated = True
                request.user.save() 

                return render(request, 'home.html')

            else:

                messages.error(request, 'Something is wrong!')
        else:
            
            form = UserFirstLoginForm()

        return render(request, 'registration/email_change.html',  {'form': form})
```

###### onlineshop/forms.py
```
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
```

## Templates
Last but not least step is about configuring settings.py file's explorer, and creating proper templates:


>Templates should directly point at the newly created "templates" folde
###### onlineshop/settings.py
```
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'social_django.context_processors.backends', # add this
                'social_django.context_processors.login_redirect', # add this
            ],
        },
    },
]
```

###### templates/base.html
```
{% load static %}
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta http-equiv="X-UA-Compatible" content="ie=edge" />
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.1.3/css/bootstrap.min.css" integrity="sha384-MCw98/SFnGE8fJT3GXwEOngsV7Zt27NXFoaoApmYm81iuXoPkFOJwJ8ERdknLPMO"
        crossorigin="anonymous" />
    <title>Task</title>
</head>
<body>
    <div class="container-fluid">
        <div>
            <h1 class="text-white text-center">{% block title %}{% endblock %}</h1>
            <div class="card p-5">
                {% block content %}
                {% endblock %}
            </div>
        </div>
    </div>
</body>
</html>
```

###### templates/home.html
```
{% extends 'base.html' %}

{% block content %}
  <p>Hi there, {{ user.email }}!</p>
{% endblock %}
```

###### templates/login.html
```
{% extends 'base.html' %}

{% block content %}
  <h2>Login</h2>
  <form method="post">
    {% csrf_token %}
    {{ form.as_p }}
    <button type="submit">Login</button>
  </form>
  <a href="{% url 'social:begin' 'google' %}">Login with Google</a><br>
  <a href="{% url 'social:begin' 'instagram' %}">Login with Instagram</a><br>
  <a href="{% url 'social:begin' 'facebook' %}">Login with Facebook</a>
{% endblock %}
```
###### templates/email_change.html
```
{% extends 'base.html' %}

{% block content %}
  <h2>Update your account information</h2>
  <form method="post">
    {% csrf_token %}
    {{ form.as_p }}
    <button type="submit">Update!</button>
  </form>
{% endblock %}
```


Final folder's structure:
```
-> src
  -> onlineshop
       __init__.py
       settings.py
       forms.py
       views.py
       urls.py
       wsgi.py
   -> users
        __init__.py
        admin.py
        apps.py
        models.py
        tests.py
        views.py
   -> templates
        -> registration
            login.html
            email_change.html
        base.html
        home.html
    manage.py
-> venv
```

## Running the application:

This action is only limited to invoking following command

```
python manage.py runserver
```
