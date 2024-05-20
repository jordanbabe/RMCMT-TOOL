from django.shortcuts import render, redirect
from django.views.generic import View
from .forms import LoginForm, CustomUserCreationForm
from django.contrib.auth import authenticate, login, logout


class LoginView(View):
    def get(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect('dashboard:dash')
        form = LoginForm()
        return render(request, 'user/login.html', {'form': form})

    def post(self, request, *args, **kwargs):
        form = LoginForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            user = authenticate(request, email=email, password=password)
            if user is not None:
                login(request, user)
                return redirect('dashboard:dash')
            else:
                error_message = "Invalid email or password."
                return render(request, 'user/login.html', {'form': form, 'error_message': error_message})
        else:
            return render(request, 'user/login.html', {'form': form})


class RegisterView(View):
    def get(self, request, *args, **kwargs):
        form = CustomUserCreationForm()
        context = {"form": form}
        return render(request, "user/register.html", context)
    
    def post(self, request, *args, **kwargs):
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            user.is_active = True
            user.save()
            return redirect("user:user_login")
        else:
            return render(request, "user/register.html", {"form": form})
        

class LogoutView(View):
    def post(self, request, *args, **kwargs):
        if request.method=="POST":
            logout(request)
            return redirect("user:user_login")