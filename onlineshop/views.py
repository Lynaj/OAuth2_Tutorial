from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, render, redirect
from .forms import *

@login_required
def home(request):

    if(request.user.email_validated == False):

        return redirect('change_email')

    return render(request, 'home.html')

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