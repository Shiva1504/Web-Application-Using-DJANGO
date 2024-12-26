from django.shortcuts import render

# Create your views here.
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth.decorators import login_required


def root_redirect_view(request):
    return redirect('login')

@login_required
def dashboard_view(request):
    return render(request, 'dashboard.html')


def login_view(request):
    if request.user.is_authenticated:
        logout(request)  # Invalidate the session
        request.session.flush()  # Clear all session data
        return redirect('login')


    if request.method == "POST":
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('home')  # Redirect to home page
        else:
            messages.error(request, 'Invalid username or password')
    return render(request, 'login.html')


@login_required
def home_view(request):
    return render(request, 'dashboard.html', {'user': request.user})

def register_view(request):
    if request.method == "POST":
        username = request.POST['username']
        email = request.POST['email']
        password1 = request.POST['password1']
        password2 = request.POST['password2']

        if password1 != password2:
            messages.error(request, "Passwords do not match!")
            return redirect('register')
        
        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists!")
            return redirect('register')

        if User.objects.filter(email=email).exists():
            messages.error(request, "Email is already in use!")
            return redirect('register')

        # Create user
        user = User.objects.create_user(username=username, email=email, password=password1)
        user.save()

        # Authenticate and login the user
        user = authenticate(request, username=username, password=password1)
        if user is not None:
            login(request, user)
            messages.success(request, "Account created and logged in successfully!")
            return redirect('home')
        else:
            messages.error(request, "Something went wrong, please try logging in.")
            return redirect('login')
    return render(request, 'register.html')

def logout_view(request):
    logout(request)
    return redirect('login')


from django.core.mail import send_mail
import random
from django.contrib import messages
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.conf import settings
from .models import UserOTP

import random
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib import messages
from .models import UserOTP

import random
from django.core.mail import send_mail
from django.conf import settings
from django.contrib import messages
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from .models import UserOTP
def forgot_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')  # Use .get() to avoid KeyError
        print(f"Received email: {email}")  # Debugging print

        # Check if the user with this email exists
        if email and User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            otp = str(random.randint(100000, 999999))  # Generate OTP

            # Create or update UserOTP for this user
            user_otp, created = UserOTP.objects.get_or_create(user=user)
            user_otp.otp = otp
            user_otp.save()

            # Send the OTP to the user's email
            send_mail(
                'Password Reset OTP',
                f'Your OTP for password reset is: {otp}',
                settings.EMAIL_HOST_USER,
                [email],
                fail_silently=False,
            )

            # Store the email in session for the next step
            request.session['reset_email'] = email

            # Redirect to the OTP verification page
            return redirect('verify_otp')
        
        else:
            print(f"Email not found: {email}")  # Debugging print
            messages.error(request, 'Email not found')
    
    return render(request, 'forgot_password.html')



def reset_password(request):
    if request.method == 'POST':
        email = request.session.get('reset_email')
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']
        
        if password == confirm_password:
            user = User.objects.get(email=email)
            user.set_password(password)
            user.save()
            
            # Clean up OTP
            UserOTP.objects.filter(user=user).delete()
            
            messages.success(request, 'Password reset successful')
            return redirect('login')
        else:
            messages.error(request, 'Passwords do not match')
    return render(request, 'reset_password.html')



from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib import messages
from .models import UserOTP  # Make sure to import UserOTP, not UserProfile

def verify_otp(request):
    if request.method == 'POST':
        entered_otp = request.POST['otp']
        email = request.session.get('reset_email')
        
        if email:
            try:
                user = User.objects.get(email=email)
                user_otp = UserOTP.objects.get(user=user)
                print(user_otp)
                if user_otp.otp == entered_otp:
                    return redirect('reset_password')
                else:
                    messages.error(request, 'Invalid OTP')
            except (User.DoesNotExist, UserOTP.DoesNotExist):
                messages.error(request, 'Something went wrong')
        else:
            messages.error(request, 'Email session expired')
    return render(request, 'verify_otp.html')

def reset_password(request):
    if request.method == 'POST':
        email = request.session.get('reset_email')
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']
        
        if password == confirm_password:
            user = User.objects.get(email=email)
            user.set_password(password)
            user.save()
            messages.success(request, 'Password has been reset successfully.')
            return redirect('login')
        
        
        else:
            messages.error(request, 'Passwords do not match')
    return render(request, 'reset_password.html')