import os
from django.contrib.auth.hashers import make_password
from rest_framework import viewsets
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .models import User,Role
from utils.custompagination import CustomPagination
import random
from utils.helpers import (
    MESSAGES, STATUS_CODES, get_user, get_role, validate_email, format_response,send_email_in_background,generate_jwt_tokens,check_blocked_user
)
from django.contrib.auth.hashers import check_password
from django.conf import settings
from django.utils.crypto import get_random_string
from django.utils import timezone
from datetime import timedelta
import threading
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from utils.aes_encryption import *
# Load disposable domains once
DISPOSABLE_DOMAINS_FILE = os.path.join(os.path.dirname(__file__), "disposable_domains.txt")
with open(DISPOSABLE_DOMAINS_FILE, "r", encoding="utf-8") as f:
    DISPOSABLE_DOMAINS = set(line.strip().lower() for line in f if line.strip())


class SignUpViewSet(viewsets.ViewSet):

    @swagger_auto_schema(
        operation_summary="Create a new user",
        operation_description="Registers a new user with the provided encrypted payload.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['data'],
            properties={
                'data': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="Encrypted payload containing user info as JSON"
                ),
            },
        ),
        responses={201: MESSAGES["user_created"], 400: "Bad Request"}
    )
    def create(self, request):
        encrypted_payload = request.data.get("data")
        if not encrypted_payload:
            return format_response(MESSAGES["all_fields_required"], status_code=STATUS_CODES["bad_request"])

        # Decrypt the payload
        decrypted_json = decrypt_aes(AES_KEY, encrypted_payload)
        
        print('decrypted json',decrypted_json)
        if not decrypted_json:
            return format_response("Invalid encrypted data", status_code=STATUS_CODES["bad_request"])

        try:
            data = json.loads(decrypted_json)
        except json.JSONDecodeError:
            return format_response("Decrypted data is not valid JSON", status_code=STATUS_CODES["bad_request"])

        # Extract fields
        name = data.get("name")
        email = data.get("email")
        role_id = data.get("role")
        password = data.get("password")
        confirm_password = data.get("confirm_password")

        # Validations
        if not all([name, email, role_id, password, confirm_password]):
            return format_response(MESSAGES["all_fields_required"], status_code=STATUS_CODES["bad_request"])

        if password != confirm_password:
            return format_response(MESSAGES["password_mismatch"], status_code=STATUS_CODES["bad_request"])

        email_error = validate_email(email, DISPOSABLE_DOMAINS)
        if email_error:
            return format_response(email_error, status_code=STATUS_CODES["bad_request"])

        role = get_role(role_id)
        if not role:
            return format_response(MESSAGES["invalid_role"], status_code=STATUS_CODES["bad_request"])

        # Create user
        User.objects.create(
            username=random.randint(1000000000, 9999999999),
            name=name,
            email=email,
            role=role,
            password=make_password(password)
        )

        return format_response(
            MESSAGES["user_created"],
            status_code=STATUS_CODES["success_created"]
        )

class UserViewSet(viewsets.ViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    """ViewSet for managing users with full CRUD and pagination."""

    # -------------------- LIST -------------------- #
    @swagger_auto_schema(
        operation_summary="List all users",
        operation_description="Fetch a paginated list of all registered users. "
                              "Supports filters: `name`, `email`, `role`. "
                              "Also supports `page` and `page_size` query params.",
        manual_parameters=[
            openapi.Parameter('page', openapi.IN_QUERY, description="Page number", type=openapi.TYPE_INTEGER, default=1),
            openapi.Parameter('page_size', openapi.IN_QUERY, description="Number of items per page", type=openapi.TYPE_INTEGER, default=10),
            openapi.Parameter('name', openapi.IN_QUERY, description="Filter by name (partial match)", type=openapi.TYPE_STRING),
            openapi.Parameter('email', openapi.IN_QUERY, description="Filter by email (partial match)", type=openapi.TYPE_STRING),
            openapi.Parameter('role', openapi.IN_QUERY, description="Filter by role ID", type=openapi.TYPE_INTEGER),
        ],
        responses={200: "Paginated list of users"}
    )
    def list(self, request):
        users = User.objects.all().order_by("-id")

        # --- Filters ---
        name = request.query_params.get("name")
        email = request.query_params.get("email")
        role = request.query_params.get("role")

        if name:
            users = users.filter(name__icontains=name)

        if email:
            users = users.filter(email__icontains=email)

        if role:
            users = users.filter(role_id=role)

        # --- Pagination ---
        paginator = CustomPagination()
        page_size = request.query_params.get("page_size")
        if page_size:
            try:
                paginator.page_size = int(page_size)
            except ValueError:
                return format_response("Invalid page_size", status_code=STATUS_CODES["bad_request"])

        paginated_users = paginator.paginate_queryset(users, request)

        data = [
            {
                "id": u.id,
                "name": u.name,
                "email": u.email,
                "role": u.role.id if u.role else None
            }
            for u in paginated_users
        ]

        response = paginator.get_paginated_response(data)
        response.data["status"] = STATUS_CODES["success_ok"]
        response.data["message"] = "Paginated users fetched successfully"
        return response

    # -------------------- RETRIEVE -------------------- #
    @swagger_auto_schema(
        operation_summary="Retrieve a user by ID",
        operation_description="Fetches the user details for the given ID.",
        responses={200: "User details", 404: "User not found"}
    )
    def retrieve(self, request, pk=None):
        user = get_user(pk)
        if not user:
            return format_response(MESSAGES["user_not_found"], status_code=STATUS_CODES["not_found"])
        return format_response(
            MESSAGES["user_list"],
            data={"id": user.id, "name": user.name, "email": user.email, "role": user.role.id if user.role else None},
            status_code=STATUS_CODES["success_ok"]
        )

    # -------------------- UPDATE -------------------- #
    @swagger_auto_schema(
        operation_summary="Update an existing user by ID",
        operation_description="Updates an existing user with the provided details.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'name': openapi.Schema(type=openapi.TYPE_STRING),
                'email': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_EMAIL),
                'role': openapi.Schema(type=openapi.TYPE_INTEGER),
                'password': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_PASSWORD),
            },
        ),
    )
    def update(self, request, pk=None):
        user = get_user(pk)
        if not user:
            return format_response(MESSAGES["user_not_found"], status_code=STATUS_CODES["not_found"])

        data = request.data
        if "name" in data:
            user.name = data["name"]

        if "email" in data:
            email_error = validate_email(data["email"], DISPOSABLE_DOMAINS, exclude_user_id=pk)
            if email_error:
                return format_response(email_error, status_code=STATUS_CODES["bad_request"])
            user.email = data["email"]

        if "role" in data:
            role = get_role(data["role"])
            if not role:
                return format_response(MESSAGES["invalid_role"], status_code=STATUS_CODES["bad_request"])
            user.role = role

        if "password" in data:
            user.password = make_password(data["password"])

        user.save()
        return format_response(MESSAGES["user_updated"], status_code=STATUS_CODES["success_ok"])

    # -------------------- DELETE -------------------- #
    @swagger_auto_schema(
        operation_summary="Delete a user by ID",
        operation_description="Deletes the user identified by the provided ID.",
        responses={200: MESSAGES["user_deleted"], 404: "User not found"}
    )
    def destroy(self, request, pk=None):
        user = get_user(pk)
        if not user:
            return format_response(MESSAGES["user_not_found"], status_code=STATUS_CODES["not_found"])
        user.delete()
        return format_response(MESSAGES["user_deleted"], status_code=STATUS_CODES["success_ok"])


class ResetPasswordViewSet(viewsets.ViewSet):
    """
    ViewSet for handling forgot password and password reset with AES encrypted payload
    """


    @swagger_auto_schema(
        operation_summary="Forgot Password",
        operation_description="Request password reset link by email. Generates a token and sends it via email.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['data'],
            properties={
                'data': openapi.Schema(type=openapi.TYPE_STRING, description='AES encrypted payload containing email')
            },
        )
    )
    
    def create(self, request):
        """Send password reset token via email (AES encrypted payload)"""
        encrypted_payload = request.data.get('data')
        if not encrypted_payload:
            return format_response(MESSAGES["all_fields_required"], status_code=STATUS_CODES["bad_request"])

        decrypted_data = decrypt_aes(AES_KEY, encrypted_payload)
        if not decrypted_data or not is_valid_json(decrypted_data):
            return format_response("Invalid encrypted payload", status_code=STATUS_CODES["bad_request"])

        data = json.loads(decrypted_data)
        email = data.get('email')
        if not email:
            return format_response(MESSAGES["all_fields_required"], status_code=STATUS_CODES["bad_request"])

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return format_response(MESSAGES["user_not_found"], status_code=STATUS_CODES["not_found"])

        # Generate token
        token = get_random_string(length=50)
        user.link_expire_token = token
        user.last_failed_login = timezone.now()
        user.save()

        # Encrypt user_id
        encrypted_user_id = encrypt_aes(AES_KEY, str(user.id))

        # Use header origin if available, fallback to localhost
        base_url = request.headers.get("Origin") or f"http://{request.get_host()}"
        reset_link = f"{base_url}/reset-password?token={token}&user_id={encrypted_user_id}"

        # Email content context for template
        context = {
            "user": user.name,
            "reset_link": reset_link,
            "message": "Click the button below to reset your password."
        }
        subject = "Password Reset Request"

        # Send email in background using HTML template
        threading.Thread(
            target=send_email_in_background,
            args=(subject, context, [user.email], "reset_password.html")
        ).start()

        # Encrypt response
        response_payload = {
            "user_id": encrypted_user_id,
            "token": token
        }
        encrypted_response = encrypt_aes(AES_KEY, json.dumps(response_payload))

        return format_response(
            MESSAGES["password_link_sent"],
            data={"data": encrypted_response},
            status_code=STATUS_CODES["success_ok"]
        )


    @swagger_auto_schema(
        operation_summary="Reset Password",
        operation_description="Reset password using token, new password and confirm password (AES encrypted payload).",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['data'],
            properties={
                'data': openapi.Schema(type=openapi.TYPE_STRING, description='AES encrypted payload containing token, new_password, confirm_password')
            },
        )
    )
    def update(self, request, pk=None):
        """Reset password using AES encrypted payload"""
        encrypted_payload = request.data.get('data')
        if not encrypted_payload:
            return format_response(MESSAGES["all_fields_required"], status_code=STATUS_CODES["bad_request"])

        decrypted_data = decrypt_aes(AES_KEY, encrypted_payload)
        if not decrypted_data or not is_valid_json(decrypted_data):
            return format_response("Invalid encrypted payload", status_code=STATUS_CODES["bad_request"])

        data = json.loads(decrypted_data)
        token = data.get('token')
        new_password = data.get('new_password')
        confirm_password = data.get('confirm_password')

        if not all([token, new_password, confirm_password]):
            return format_response(MESSAGES["all_fields_required"], status_code=STATUS_CODES["bad_request"])

        if new_password != confirm_password:
            return format_response(MESSAGES["password_mismatch"], status_code=STATUS_CODES["bad_request"])

        try:
            user = User.objects.get(link_expire_token=token)
        except User.DoesNotExist:
            return format_response(MESSAGES["invalid_token"], status_code=STATUS_CODES["bad_request"])

        # Update password and clear token
        user.set_password(new_password)
        user.link_expire_token = ""
        user.save()

        return format_response(
            MESSAGES["password_reset_success"],
            status_code=STATUS_CODES["success_ok"]
        )


class ValidateResetTokenViewSet(viewsets.ViewSet):
    """
    ViewSet to validate password reset token (AES encrypted payload)
    """

    @swagger_auto_schema(
        operation_summary="Validate Reset Token",
        operation_description="Check if password reset token is valid and not expired (AES encrypted payload).",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['data'],
            properties={
                'data': openapi.Schema(
                    type=openapi.TYPE_STRING, 
                    description='AES encrypted payload containing token'
                ),
            }
        )
    )
    def create(self, request):
        encrypted_payload = request.data.get('data')
        if not encrypted_payload:
            return format_response(MESSAGES["all_fields_required"], status_code=STATUS_CODES["bad_request"])

        # Decrypt incoming payload
        decrypted_data = decrypt_aes(AES_KEY, encrypted_payload)
        if not decrypted_data or not is_valid_json(decrypted_data):
            return format_response("Invalid encrypted payload", status_code=STATUS_CODES["bad_request"])

        data = json.loads(decrypted_data)
        token = data.get('token')
        if not token:
            return format_response(MESSAGES["all_fields_required"], status_code=STATUS_CODES["bad_request"])

        # Validate token
        try:
            user = User.objects.get(link_expire_token=token)
        except User.DoesNotExist:
            return format_response(MESSAGES["invalid_token"], status_code=STATUS_CODES["bad_request"])

        # Check token expiration (10 minutes)
        token_age = timezone.now() - user.last_failed_login
        if token_age > timedelta(minutes=10):
            return format_response(MESSAGES["invalid_token"], status_code=STATUS_CODES["bad_request"])

        # Encrypt response payload
        response_payload = {
            "user_id": str(user.id),  # Convert to string before encryption
            "token": user.link_expire_token
        }
        encrypted_response = encrypt_aes(AES_KEY, json.dumps(response_payload))

        return format_response(
            MESSAGES["token_valid"],
            data={"data": encrypted_response},
            status_code=STATUS_CODES["success_ok"]
        )

class LoginViewSet(viewsets.ViewSet):
    """
    ViewSet for user login with AES encrypted payload and JWT generation
    """

    @swagger_auto_schema(
        operation_summary="User Login",
        operation_description="Authenticate user and return JWT tokens (AES encrypted payload).",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['data'],
            properties={
                'data': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='AES encrypted payload containing email and password'
                ),
            },
        ),
        responses={200: "Login successful with encrypted tokens", 400: "Bad Request", 401: "Unauthorized", 429: "Too Many Requests"}
    )
    def create(self, request):
        encrypted_payload = request.data.get('data')
        if not encrypted_payload:
            return format_response(
                MESSAGES["all_fields_required"],
                status_code=STATUS_CODES["bad_request"]
            )

        # Decrypt incoming payload
        decrypted_data = decrypt_aes(AES_KEY, encrypted_payload)
        if not decrypted_data or not is_valid_json(decrypted_data):
            return format_response("Invalid encrypted payload", status_code=STATUS_CODES["bad_request"])

        data = json.loads(decrypted_data)
        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            return format_response(
                MESSAGES["all_fields_required"],
                status_code=STATUS_CODES["bad_request"]
            )

        user = User.objects.filter(email=email).first()
        if not user:
            return format_response(
                MESSAGES["invalid_credentials"],
                status_code=STATUS_CODES["bad_request"]
            )

        # Check if user is blocked
        is_blocked, block_message = check_blocked_user(user)
        if is_blocked:
            return format_response(MESSAGES["block_user"], status_code=STATUS_CODES["too_many_requests"])

        # Check password
        if not check_password(password, user.password):
            user.failed_login_attempts += 1
            user.last_failed_login = timezone.now()
            user.save()
            return format_response(MESSAGES["invalid_credentials"], status_code=STATUS_CODES["bad_request"])

        # Reset failed attempts on successful login
        user.failed_login_attempts = 0
        user.last_failed_login = None
        user.save()

        # Generate JWT tokens
        access_token, refresh_token = generate_jwt_tokens(user)

        response_payload = {
            "user_id": str(user.id),  # Convert to string for encryption
            "name": user.name,
            "email": user.email,
            "role_id": str(user.role.id) if user.role else None,
            "role_name": user.role.name if user.role else None,
            "access_token": access_token,
            "refresh_token": refresh_token,
        }

        # Encrypt response
        encrypted_response = encrypt_aes(AES_KEY, json.dumps(response_payload))

        return format_response(
            MESSAGES["login_success"],
            data={"data": encrypted_response},
            status_code=STATUS_CODES["success_ok"]
        )

class RoleViewSet(viewsets.ViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    """
    ViewSet for listing roles
    """
 
    @swagger_auto_schema(
        operation_summary="List Roles",
        operation_description="Retrieve a list of all roles (active/inactive).",
        responses={
            200: openapi.Response(
                description="List of roles",
                examples={
                    "application/json": {
                        "message": MESSAGES["user_list"],   # You can also create `role_list` in MESSAGES
                        "status": STATUS_CODES["success_ok"],
                        "data": [
                            {"id": 1, "name": "Admin", "is_active": True},
                            {"id": 2, "name": "User", "is_active": True},
                            {"id": 3, "name": "Guest", "is_active": False},
                        ],
                    }
                },
            )
        },
    )
    def list(self, request):
        """GET /roles/ → List all roles"""
        roles = list(Role.objects.all().values("id", "name", "is_active"))
        return format_response(
            message="Role list fetched successfully",  # you can also add `"role_list": "Role list fetched successfully"` in MESSAGES
            data=roles,
            status_code=STATUS_CODES["success_ok"]
        )