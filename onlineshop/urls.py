from django.contrib import admin
from django.urls import path
from django.conf.urls import include, url
from django.contrib.auth.views import LoginView, LogoutView
from .views import *

urlpatterns = [
	url(r'^$', home, name='home'),
    url(r'^change/$', change_email, name='change_email'),
    url(r'^login/$', LoginView.as_view(), name='login'),
    url(r'^logout/$', LogoutView.as_view(), name='logout'),
    path('admin/', admin.site.urls),
    path('social-auth/', include('social_django.urls', namespace="social"))
]