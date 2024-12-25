import random
from django.core.mail import send_mail

def generate_otp():
    """
    Generate a 6-digit OTP
    """
    return random.randint(100000, 999999)

def send_otp_email(email, otp):
    """
    Send an OTP to the user's email address
    """
    subject = 'Your OTP for Password Reset'
    message = f'Your OTP for password reset is {otp}.'
    from_email = 'your_email@example.com'  # Replace with your email
    recipient_list = [email]

    send_mail(subject, message, from_email, recipient_list)
