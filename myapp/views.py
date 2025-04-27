from django.shortcuts import render, redirect
from django.contrib.auth import login as auth_login, authenticate, logout as auth_logout
from django.contrib.auth.decorators import login_required
from .models import CustomUser
from django.contrib import messages
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.decorators import login_required


def register(request):
    if request.method == 'POST':
        username = request.POST['username']
        first_name = request.POST['first_name']
        last_name = request.POST['last_name']
        email = request.POST['email']
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']

        # Username validation
        if ' ' in username:
            messages.error(request, "Username cannot contain spaces.")
            return render(request, 'register.html')
        if username[0].isdigit():
            messages.error(request, "Username cannot start with a digit.")
            return render(request, 'register.html')
        if len(username) <= 3:
            messages.error(request, "Username is too short.")
            return render(request, 'register.html')
        if CustomUser.objects.filter(username=username).exists():
            messages.error(request, "Username is already taken.")
            return render(request, 'register.html')

        # Password validation
        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return render(request, 'register.html')
        if len(password) < 8:
            messages.error(request, "Password must be at least 8 characters long.")
            return render(request, 'register.html')
        if not any(char.isdigit() for char in password):   
            messages.error(request, "Password must contain at least one number.")
            return render(request, 'register.html')
        if not any(char.isalpha() for char in password):
            messages.error(request, "Password must contain at least one letter.")
            return render(request, 'register.html')

        user = CustomUser.objects.create_user(
            username=username,
            password=password,
            email=email,
            first_name=first_name,
            last_name=last_name
        )
        user.save()
        auth_login(request, user)
        messages.success(request, "User is successfully Register")  
        return redirect('login')

    return render(request, 'register.html')

def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            auth_login(request, user)
            request.session['username']=username
            request.session['password']=password
            return redirect('dashboard')
        else:
            messages.error(request, "Invalid username or password.")
            return render(request, 'login.html')

    return render(request, 'login.html')

@login_required
def dashboard(request):
    return render(request, 'dashboard.html')

@login_required
def profile(request):
    user = request.user
    if request.method == 'POST':
        username= request.POST.get('username', user.username)
        first_name = request.POST.get('first_name', user.first_name)
        last_name = request.POST.get('last_name', user.last_name)
        email = request.POST.get('email', user.email)
        address = request.POST.get('address', user.address)
        phone_number = request.POST.get('phone_number', user.phone_number)

        # Validation
        if ' ' in username:
            messages.error(request, "Username cannot contain spaces.")
            return render(request, 'profile.html')
        if not address or address.strip() == '':
            messages.error(request, "Address cannot be empty.")
        elif not phone_number or phone_number.strip() == '':
            messages.error(request, "Phone number cannot be empty.")
        elif len(phone_number) > 12:
            messages.error(request, "Phone number cannot be more than 12 characters.")
        elif CustomUser.objects.filter(username=username).exclude(pk=user.pk).exists():
            messages.error(request, "This username is already taken. Please choose another one.")
        elif CustomUser.objects.filter(email=email).exclude(pk=user.pk).exists():
            messages.error(request, "This email is already in use. Please choose another one.")
        #elif CustomUser.objects.filter(phone_number=phone_number).exclude(pk=user.pk).exists():
         #   messages.error(request, "This Phone_number is already in use. Please choose another one.")
        
        else:
            user.username=username
            user.first_name = first_name
            user.last_name = last_name
            user.email = email
            user.address = address
            user.phone_number = phone_number
            user.save()
            messages.success(request, "Your profile has been updated successfully!")  

    return render(request, 'profile.html', {'user': user})

def logout_view(request):
    auth_logout(request)
    return redirect('login')

# Password reset logic

@login_required
def password_reset_request(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        
        if not username:
            messages.error(request, "Please fill out this field.")
        elif CustomUser.objects.filter(username=username).exists():
            user = CustomUser.objects.get(username=username)
            uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            return redirect('password_reset_confirm', uidb64=uidb64, token=token)
        else:
            messages.error(request, "No account found with this username.")
    
    return render(request, 'password_reset.html')

def password_reset_confirm(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = CustomUser.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, CustomUser.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        if request.method == 'POST':
            new_password = request.POST.get('new_password')
            confirm_password = request.POST.get('confirm_password')

            if new_password == confirm_password:
                user.set_password(new_password)
                user.save()
                messages.success(request, "Password has been reset successfully!")
                return redirect('login')
            else:
                messages.error(request, "Passwords do not match.")

        return render(request, 'password_reset_confirm.html', {'uidb64': uidb64, 'token': token})
    else:
        messages.error(request, "The password reset link is invalid.")
        return redirect('password_reset_request')
