from django.contrib.auth.hashers import make_password
from rest_framework.response import Response
from rest_framework import status
from users.models import User, Role  # absolute import
from django.conf import settings
from datetime import timedelta
from django.utils import timezone
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string

# -------------------- Centralized messages --------------------
MESSAGES = {
    "all_fields_required": "All fields are required",
    "password_mismatch": "Passwords do not match",
    "email_exists": "Email already exists",
    "disposable_email": "Disposable email domain not allowed",
    "invalid_role": "Invalid role",
    "user_not_found": "User not found",
    "user_created": "User created successfully",
    "user_updated": "User updated successfully",
    "user_deleted": "User deleted successfully",
    "user_list": "User list fetched successfully",
    "password_link_sent": "Password reset link sent to email",
    "password_reset_success": "Password reset successfully",
    "invalid_token": "Invalid or expired token",
    "token_valid": "Token is valid",
    "too_many_attempts": "Too many failed login attempts. Please try again later.",
    "invalid_credentials": "Invalid email or password",
    "login_success": "Login successful",
    "block_user": "User is blocked due to multiple failed login attempts",
    "unauthorized": "Unauthorized access or Invalid token",
    # ----------------- Category Messages ----------------------- #
    "category_created": "Category created successfully",
    "category_updated": "Category updated successfully",
    "category_deleted": "Category deleted successfully",
    "category_not_found": "Category not found",
    "category_retrieved": "Category fetched successfully",
    "category_list": "Category list fetched successfully",
    
    # ----------------- Slot Messages ----------------------- #
   
    "slot_created": "Slot created successfully",
    "slot_updated": "Slot updated successfully",
    "slot_deleted": "Slot deleted successfully",
    "slot_not_found": "Slot not found",
    "slot_retrieved": "Slot fetched successfully",
    "slot_list": "Slot list fetched successfully",
    "slot_overlap": "Slot overlaps with an existing slot in the same category",
    "slot_invalid_time": "End time must be greater than start time",
    "slot_invalid_datetime": "Invalid datetime format. Use ISO 8601 format (e.g. 2025-09-12T12:30:21Z).",
    
    # ----------------- Booking Messages ----------------------- #
    "booking_created": "Booking created successfully",
    "booking_updated": "Booking updated successfully",
    "booking_deleted": "Booking deleted successfully",
    "booking_not_found": "Booking not found",
    "booking_retrieved": "Booking fetched successfully",
    "booking_list": "Booking list fetched successfully",
    "slot_already_booked": "This slot is already booked by another user",
}

# -------------------- Centralized status codes ----------------- #
STATUS_CODES = {
    "success_created": status.HTTP_201_CREATED,
    "success_ok": status.HTTP_200_OK,
    "bad_request": status.HTTP_400_BAD_REQUEST,
    "not_found": status.HTTP_404_NOT_FOUND,
    "too_many_requests": status.HTTP_429_TOO_MANY_REQUESTS,
    "unauthorized": status.HTTP_401_UNAUTHORIZED,
}

# -------------------- Helper methods -------------------------- #
def get_user(pk):
    try:
        return User.objects.get(pk=pk)
    except User.DoesNotExist:
        return None

def get_role(role_id):
    try:
        return Role.objects.get(id=role_id)
    except Role.DoesNotExist:
        return None

def validate_email(email, disposable_domains=set(), exclude_user_id=None):
    if User.objects.exclude(pk=exclude_user_id).filter(email=email).exists():
        return MESSAGES["email_exists"]
    domain = email.split("@")[-1].lower()
    if domain in disposable_domains:
        return MESSAGES["disposable_email"]
    return None

def format_response(message=None, data=None, status_code=STATUS_CODES["success_ok"]):
    return Response({
        "message": message,
        "status": status_code,
        "data": data
    }, status=status_code)


def send_email_in_background(subject, context, recipient_list, template_name="emails/reset_password.html"):
    """Send HTML email in a background thread"""
    html_message = render_to_string(template_name, context)
    text_message = f"{subject}\n\n{context.get('message', '')}"

    email = EmailMultiAlternatives(
        subject=subject,
        body=text_message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=recipient_list
    )
    email.attach_alternative(html_message, "text/html")
    email.send(fail_silently=False)
    

def generate_jwt_tokens(user):
    """Generate access and refresh tokens for a user"""
    refresh = RefreshToken.for_user(user)
    return str(refresh.access_token), str(refresh)

def check_blocked_user(user, max_attempts=5, block_minutes=5):
    """
    Check if a user is blocked due to too many failed login attempts.
    Returns a tuple: (is_blocked: bool, message: str)
    """
    if user.failed_login_attempts >= max_attempts:
        if user.last_failed_login:
            block_time = user.last_failed_login + timedelta(minutes=block_minutes)
            if timezone.now() < block_time:
                wait_time = int((block_time - timezone.now()).total_seconds() // 60) + 1
                return True, f"Too many failed attempts. Try again after {wait_time} minutes."
    return False, ""
