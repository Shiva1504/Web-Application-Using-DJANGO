from django.urls import path
from django.views.generic.base import RedirectView
from .views import login_view, home_view,register_view, logout_view, root_redirect_view
from django.urls import path
from . import views

urlpatterns = [
    path('', root_redirect_view, name='login'),  # Redirect root to login
    path('login/', login_view, name='login'),
    path('register/', register_view, name='register'),
    path('home/', home_view, name='home'),
    path('logout/', logout_view, name='logout'),
     path('forgot-password/', views.forgot_password, name='forgot_password'),
    path('verify-otp/', views.verify_otp, name='verify_otp'),
    path('reset-password/', views.reset_password, name='reset_password'),
]

