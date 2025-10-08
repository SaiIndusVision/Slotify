import pytest
import random
import json
import os
import binascii
from django.urls import reverse
from rest_framework import status
from django.contrib.auth.hashers import make_password, check_password
from users.models import User, Role
from rest_framework.test import APIClient
from django.utils import timezone
from datetime import timedelta
from unittest.mock import patch
from utils.aes_encryption import encrypt_aes, decrypt_aes, is_valid_json
from rest_framework_simplejwt.tokens import RefreshToken
from django.conf import settings

# Load AES_KEY from environment, matching aes_encryption.py
base64_key = os.getenv("AES_KEY", "3136627974657365637265746b6579")  # Fallback hex-encoded 16-byte key
try:
    AES_KEY = binascii.unhexlify(base64_key)
except binascii.Error as e:
    raise ValueError(f"Invalid AES_KEY: {e}")

@pytest.fixture
def api_client():
    """Fixture to provide a REST API client."""
    return APIClient()

@pytest.fixture
def role(db):
    """Fixture to create a test role."""
    return Role.objects.create(name="Test Role", id=1)

@pytest.fixture
def user(db, role):
    """Fixture to create a test user."""
    return User.objects.create(
        username=str(random.randint(1000000000, 9999999999)),
        name="Test User",
        email="test@example.com",
        role=role,
        password=make_password("password123")
    )

@pytest.fixture
def authenticated_client(api_client, user):
    """Fixture to provide an authenticated API client with JWT token."""
    refresh = RefreshToken.for_user(user)
    api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')
    return api_client

@pytest.mark.django_db
class TestSignUpViewSet:
    """Test cases for SignUpViewSet create operation with AES encrypted payload."""

    def test_create_user_success(self, api_client, role):
        """Test successful user creation."""
        payload = {
            "name": "New User",
            "email": "newuser@example.com",
            "role": role.id,
            "password": "testpass123",
            "confirm_password": "testpass123"
        }
        encrypted_payload = encrypt_aes(AES_KEY, json.dumps(payload))
        response = api_client.post(
            reverse('signup-list'),
            data={"data": encrypted_payload},
            format='json'
        )

        assert response.status_code == status.HTTP_201_CREATED
        assert response.data['message'] == "User created successfully"
        assert User.objects.filter(email="newuser@example.com").exists()
        user = User.objects.get(email="newuser@example.com")
        assert user.name == "New User"
        assert user.role.id == role.id
        assert user.username.isdigit() and len(user.username) == 10

    def test_create_user_missing_fields(self, api_client, role):
        """Test user creation with missing fields."""
        payload = {
            "name": "New User",
            "email": "newuser@example.com",
            "role": role.id,
            # Missing password and confirm_password
        }
        encrypted_payload = encrypt_aes(AES_KEY, json.dumps(payload))
        response = api_client.post(
            reverse('signup-list'),
            data={"data": encrypted_payload},
            format='json'
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data['message'] == "All fields are required"

    def test_create_user_password_mismatch(self, api_client, role):
        """Test user creation with mismatched passwords."""
        payload = {
            "name": "New User",
            "email": "newuser@example.com",
            "role": role.id,
            "password": "testpass123",
            "confirm_password": "differentpass123"
        }
        encrypted_payload = encrypt_aes(AES_KEY, json.dumps(payload))
        response = api_client.post(
            reverse('signup-list'),
            data={"data": encrypted_payload},
            format='json'
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data['message'] == "Passwords do not match"

    def test_create_user_invalid_email(self, api_client, role, mocker):
        """Test user creation with invalid email format."""
        mocker.patch('users.views.validate_email', return_value="Invalid email format")
        payload = {
            "name": "New User",
            "email": "invalid-email",
            "role": role.id,
            "password": "testpass123",
            "confirm_password": "testpass123"
        }
        encrypted_payload = encrypt_aes(AES_KEY, json.dumps(payload))
        response = api_client.post(
            reverse('signup-list'),
            data={"data": encrypted_payload},
            format='json'
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data['message'] == "Invalid email format"
        assert not User.objects.filter(email="invalid-email").exists()

    def test_create_user_disposable_email(self, api_client, role, mocker):
        """Test user creation with disposable email domain."""
        mocker.patch('users.views.DISPOSABLE_DOMAINS', {'disposable.com'})
        payload = {
            "name": "New User",
            "email": "user@disposable.com",
            "role": role.id,
            "password": "testpass123",
            "confirm_password": "testpass123"
        }
        encrypted_payload = encrypt_aes(AES_KEY, json.dumps(payload))
        response = api_client.post(
            reverse('signup-list'),
            data={"data": encrypted_payload},
            format='json'
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data['message'] == "Disposable email domain not allowed"
        assert not User.objects.filter(email="user@disposable.com").exists()

    def test_create_user_invalid_role(self, api_client):
        """Test user creation with invalid role ID."""
        payload = {
            "name": "New User",
            "email": "newuser@example.com",
            "role": 999,  # Non-existent role
            "password": "testpass123",
            "confirm_password": "testpass123"
        }
        encrypted_payload = encrypt_aes(AES_KEY, json.dumps(payload))
        response = api_client.post(
            reverse('signup-list'),
            data={"data": encrypted_payload},
            format='json'
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data['message'] == "Invalid role"
        assert not User.objects.filter(email="newuser@example.com").exists()

@pytest.mark.django_db
class TestUserViewSet:
    """Test cases for UserViewSet CRUD operations."""

    def test_list_users(self, authenticated_client, user):
        """Test listing all users with pagination."""
        response = authenticated_client.get(reverse('user-list'))
        assert response.status_code == status.HTTP_200_OK
        assert response.data['message'] == "Paginated users fetched successfully"
        assert len(response.data['data']) == 1
        assert response.data['data'][0]['email'] == "test@example.com"
        assert response.data['data'][0]['name'] == "Test User"
        assert response.data['data'][0]['role'] == user.role.id

    def test_list_users_empty(self, authenticated_client, role):
        """Test listing users when no additional users exist beyond the authenticated user."""
        # Delete all users except the authenticated one (handled by fixture)
        User.objects.exclude(email="test@example.com").delete()
        response = authenticated_client.get(reverse('user-list'))
        assert response.status_code == status.HTTP_200_OK
        assert response.data['message'] == "Paginated users fetched successfully"
        assert len(response.data['data']) == 1  # Expecting only the authenticated user
        assert response.data['data'][0]['email'] == "test@example.com"

    def test_list_users_filter_by_name(self, authenticated_client, user):
        """Test filtering users by name (partial match)."""
        response = authenticated_client.get(reverse('user-list'), {'name': 'Test'})
        assert response.status_code == status.HTTP_200_OK
        assert response.data['message'] == "Paginated users fetched successfully"
        assert len(response.data['data']) == 1
        assert response.data['data'][0]['email'] == "test@example.com"

    def test_list_users_filter_by_email(self, authenticated_client, user):
        """Test filtering users by email (partial match)."""
        response = authenticated_client.get(reverse('user-list'), {'email': 'example.com'})
        assert response.status_code == status.HTTP_200_OK
        assert response.data['message'] == "Paginated users fetched successfully"
        assert len(response.data['data']) == 1
        assert response.data['data'][0]['email'] == "test@example.com"

    def test_list_users_filter_by_role(self, authenticated_client, user, role):
        """Test filtering users by role ID."""
        response = authenticated_client.get(reverse('user-list'), {'role': role.id})
        assert response.status_code == status.HTTP_200_OK
        assert response.data['message'] == "Paginated users fetched successfully"
        assert len(response.data['data']) == 1
        assert response.data['data'][0]['role'] == role.id

    def test_list_users_invalid_page_size(self, authenticated_client):
        """Test listing users with invalid page_size."""
        response = authenticated_client.get(reverse('user-list'), {'page_size': 'invalid'})
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data['message'] == "Invalid page_size"

    def test_retrieve_user_success(self, authenticated_client, user):
        """Test retrieving a user by ID."""
        response = authenticated_client.get(reverse('user-detail', kwargs={'pk': user.id}))
        assert response.status_code == status.HTTP_200_OK
        assert response.data['message'] == "User list fetched successfully"
        assert response.data['data']['email'] == "test@example.com"
        assert response.data['data']['name'] == "Test User"
        assert response.data['data']['role'] == user.role.id

    def test_retrieve_user_not_found(self, authenticated_client):
        """Test retrieving a non-existent user."""
        response = authenticated_client.get(reverse('user-detail', kwargs={'pk': 999}))
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert response.data['message'] == "User not found"

    def test_update_user_success(self, authenticated_client, user, role):
        """Test updating a user's details."""
        data = {
            "name": "Updated User",
            "email": "updated@example.com",
            "role": role.id,
            "password": "newpass123"
        }
        response = authenticated_client.put(reverse('user-detail', kwargs={'pk': user.id}), data, format='json')
        assert response.status_code == status.HTTP_200_OK
        assert response.data['message'] == "User updated successfully"
        user.refresh_from_db()
        assert user.name == "Updated User"
        assert user.email == "updated@example.com"
        assert user.role.id == role.id
        assert user.check_password("newpass123")

    def test_update_user_partial(self, authenticated_client, user):
        """Test partially updating a user's details."""
        data = {
            "name": "Partially Updated User"
        }
        response = authenticated_client.put(reverse('user-detail', kwargs={'pk': user.id}), data, format='json')
        assert response.status_code == status.HTTP_200_OK
        assert response.data['message'] == "User updated successfully"
        user.refresh_from_db()
        assert user.name == "Partially Updated User"
        assert user.email == "test@example.com"  # Unchanged
        assert user.check_password("password123")  # Unchanged

    def test_update_user_invalid_email(self, authenticated_client, user, mocker):
        """Test updating a user with invalid email format."""
        mocker.patch('users.views.validate_email', return_value="Invalid email format")
        data = {
            "email": "invalid-email"
        }
        response = authenticated_client.put(reverse('user-detail', kwargs={'pk': user.id}), data, format='json')
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data['message'] == "Invalid email format"
        user.refresh_from_db()
        assert user.email == "test@example.com"  # Unchanged

    def test_update_user_disposable_email(self, authenticated_client, user, mocker):
        """Test updating a user with disposable email domain."""
        mocker.patch('users.views.DISPOSABLE_DOMAINS', {'disposable.com'})
        data = {
            "email": "user@disposable.com"
        }
        response = authenticated_client.put(reverse('user-detail', kwargs={'pk': user.id}), data, format='json')
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data['message'] == "Disposable email domain not allowed"
        user.refresh_from_db()
        assert user.email == "test@example.com"  # Unchanged

    def test_update_user_invalid_role(self, authenticated_client, user):
        """Test updating a user with invalid role."""
        data = {
            "role": 999  # Non-existent role
        }
        response = authenticated_client.put(reverse('user-detail', kwargs={'pk': user.id}), data, format='json')
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data['message'] == "Invalid role"
        user.refresh_from_db()
        assert user.role.id == 1  # Unchanged

    def test_update_user_not_found(self, authenticated_client, role):
        """Test updating a non-existent user."""
        data = {
            "name": "Non-existent User",
            "email": "nonexistent@example.com",
            "role": role.id
        }
        response = authenticated_client.put(reverse('user-detail', kwargs={'pk': 999}), data, format='json')
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert response.data['message'] == "User not found"

    def test_delete_user_success(self, authenticated_client, user):
        """Test deleting a user."""
        response = authenticated_client.delete(reverse('user-detail', kwargs={'pk': user.id}))
        assert response.status_code == status.HTTP_200_OK
        assert response.data['message'] == "User deleted successfully"
        assert not User.objects.filter(id=user.id).exists()

    def test_delete_user_not_found(self, authenticated_client):
        """Test deleting a non-existent user."""
        response = authenticated_client.delete(reverse('user-detail', kwargs={'pk': 999}))
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert response.data['message'] == "User not found"

@pytest.fixture
def user_with_token(db, role):
    """Fixture to create a test user with a reset token."""
    user = User.objects.create(
        username=str(random.randint(1000000000, 9999999999)),
        name="Token User",
        email="tokenuser@example.com",
        role=role,
        password=make_password("password123"),
        link_expire_token="test-token-123",
        last_failed_login=timezone.now()
    )
    return user

@pytest.mark.django_db
class TestResetPasswordViewSet:
    """Test cases for ResetPasswordViewSet create and update operations."""

    @patch('users.views.send_email_in_background')
    def test_forgot_password_success(self, mock_send_email, api_client, user):
        """Test successful forgot password request."""
        payload = {"email": "test@example.com"}
        encrypted_payload = encrypt_aes(AES_KEY, json.dumps(payload))
        response = api_client.post(
            reverse('reset_password-list'),
            data={"data": encrypted_payload},
            format='json'
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data['message'] == "Password reset link sent to email"
        assert response.data['status'] == status.HTTP_200_OK
        assert 'data' in response.data
        decrypted_response = decrypt_aes(AES_KEY, response.data['data']['data'])
        response_data = json.loads(decrypted_response)
        assert response_data['user_id'] == encrypt_aes(AES_KEY, str(user.id))
        assert 'token' in response_data
        user.refresh_from_db()
        assert user.link_expire_token is not None
        assert user.last_failed_login is not None
        mock_send_email.assert_called_once()

    def test_forgot_password_missing_email(self, api_client):
        """Test forgot password with missing email."""
        payload = {}
        encrypted_payload = encrypt_aes(AES_KEY, json.dumps(payload))
        response = api_client.post(
            reverse('reset_password-list'),
            data={"data": encrypted_payload},
            format='json'
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data['message'] == "All fields are required"
        assert response.data['status'] == status.HTTP_400_BAD_REQUEST

    def test_forgot_password_non_existent_email(self, api_client):
        """Test forgot password with non-existent email."""
        payload = {"email": "nonexistent@example.com"}
        encrypted_payload = encrypt_aes(AES_KEY, json.dumps(payload))
        response = api_client.post(
            reverse('reset_password-list'),
            data={"data": encrypted_payload},
            format='json'
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert response.data['message'] == "User not found"
        assert response.data['status'] == status.HTTP_404_NOT_FOUND

    def test_reset_password_success(self, api_client, user_with_token):
        """Test successful password reset."""
        payload = {
            "token": "test-token-123",
            "new_password": "newpass123",
            "confirm_password": "newpass123"
        }
        encrypted_payload = encrypt_aes(AES_KEY, json.dumps(payload))
        response = api_client.put(
            reverse('reset_password-detail', kwargs={'pk': user_with_token.id}),
            data={"data": encrypted_payload},
            format='json'
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data['message'] == "Password reset successfully"
        assert response.data['status'] == status.HTTP_200_OK
        user_with_token.refresh_from_db()
        assert user_with_token.check_password("newpass123")
        assert user_with_token.link_expire_token == ""

    def test_reset_password_missing_fields(self, api_client, user_with_token):
        """Test password reset with missing fields."""
        payload = {"token": "test-token-123"}
        encrypted_payload = encrypt_aes(AES_KEY, json.dumps(payload))
        response = api_client.put(
            reverse('reset_password-detail', kwargs={'pk': user_with_token.id}),
            data={"data": encrypted_payload},
            format='json'
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data['message'] == "All fields are required"
        assert response.data['status'] == status.HTTP_400_BAD_REQUEST
        user_with_token.refresh_from_db()
        assert user_with_token.check_password("password123")  # Unchanged

    def test_reset_password_mismatch(self, api_client, user_with_token):
        """Test password reset with mismatched passwords."""
        payload = {
            "token": "test-token-123",
            "new_password": "newpass123",
            "confirm_password": "differentpass123"
        }
        encrypted_payload = encrypt_aes(AES_KEY, json.dumps(payload))
        response = api_client.put(
            reverse('reset_password-detail', kwargs={'pk': user_with_token.id}),
            data={"data": encrypted_payload},
            format='json'
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data['message'] == "Passwords do not match"
        assert response.data['status'] == status.HTTP_400_BAD_REQUEST
        user_with_token.refresh_from_db()
        assert user_with_token.check_password("password123")  # Unchanged

    def test_reset_password_invalid_token(self, api_client, user_with_token):
        """Test password reset with invalid token."""
        payload = {
            "token": "invalid-token",
            "new_password": "newpass123",
            "confirm_password": "newpass123"
        }
        encrypted_payload = encrypt_aes(AES_KEY, json.dumps(payload))
        response = api_client.put(
            reverse('reset_password-detail', kwargs={'pk': user_with_token.id}),
            data={"data": encrypted_payload},
            format='json'
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data['message'] == "Invalid or expired token"
        assert response.data['status'] == status.HTTP_400_BAD_REQUEST
        user_with_token.refresh_from_db()
        assert user_with_token.check_password("password123")  # Unchanged

@pytest.mark.django_db
class TestValidateResetTokenViewSet:
    """Test cases for ValidateResetTokenViewSet create operation."""

    def test_validate_token_success(self, api_client, user_with_token):
        """Test validating a valid token."""
        payload = {"token": "test-token-123"}
        encrypted_payload = encrypt_aes(AES_KEY, json.dumps(payload))
        response = api_client.post(
            reverse('validate_token-list'),
            data={"data": encrypted_payload},
            format='json'
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data['message'] == "Token is valid"
        assert response.data['status'] == status.HTTP_200_OK
        assert 'data' in response.data
        decrypted_response = decrypt_aes(AES_KEY, response.data['data']['data'])
        response_data = json.loads(decrypted_response)
        assert response_data['user_id'] == str(user_with_token.id)
        assert response_data['token'] == "test-token-123"

    def test_validate_token_missing_token(self, api_client):
        """Test validating with missing token."""
        payload = {}
        encrypted_payload = encrypt_aes(AES_KEY, json.dumps(payload))
        response = api_client.post(
            reverse('validate_token-list'),
            data={"data": encrypted_payload},
            format='json'
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data['message'] == "All fields are required"
        assert response.data['status'] == status.HTTP_400_BAD_REQUEST

    def test_validate_token_invalid_token(self, api_client):
        """Test validating an invalid token."""
        payload = {"token": "invalid-token"}
        encrypted_payload = encrypt_aes(AES_KEY, json.dumps(payload))
        response = api_client.post(
            reverse('validate_token-list'),
            data={"data": encrypted_payload},
            format='json'
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data['message'] == "Invalid or expired token"
        assert response.data['status'] == status.HTTP_400_BAD_REQUEST

    def test_validate_token_expired(self, api_client, user_with_token):
        """Test validating an expired token."""
        user_with_token.last_failed_login = timezone.now() - timedelta(minutes=11)
        user_with_token.save()
        payload = {"token": "test-token-123"}
        encrypted_payload = encrypt_aes(AES_KEY, json.dumps(payload))
        response = api_client.post(
            reverse('validate_token-list'),
            data={"data": encrypted_payload},
            format='json'
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data['message'] == "Invalid or expired token"
        assert response.data['status'] == status.HTTP_400_BAD_REQUEST

@pytest.mark.django_db
class TestLoginViewSet:
    """Test cases for LoginViewSet create operation."""

    @patch('users.views.generate_jwt_tokens', return_value=("access_token_123", "refresh_token_123"))
    def test_login_success(self, mock_generate_jwt_tokens, api_client, user):
        """Test successful login with valid credentials."""
        payload = {"email": "test@example.com", "password": "password123"}
        encrypted_payload = encrypt_aes(AES_KEY, json.dumps(payload))
        response = api_client.post(
            reverse('login-list'),
            data={"data": encrypted_payload},
            format='json'
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data['message'] == "Login successful"
        assert response.data['status'] == status.HTTP_200_OK
        assert 'data' in response.data
        decrypted_response = decrypt_aes(AES_KEY, response.data['data']['data'])
        response_data = json.loads(decrypted_response)
        assert response_data['user_id'] == str(user.id)
        assert response_data['name'] == "Test User"
        assert response_data['email'] == "test@example.com"
        assert response_data['role_id'] == str(user.role.id)
        assert response_data['role_name'] == "Test Role"
        assert response_data['access_token'] == "access_token_123"
        assert response_data['refresh_token'] == "refresh_token_123"
        user.refresh_from_db()
        assert user.failed_login_attempts == 0
        assert user.last_failed_login is None

    def test_login_missing_fields(self, api_client):
        """Test login with missing fields."""
        payload = {"email": "test@example.com"}
        encrypted_payload = encrypt_aes(AES_KEY, json.dumps(payload))
        response = api_client.post(
            reverse('login-list'),
            data={"data": encrypted_payload},
            format='json'
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data['message'] == "All fields are required"
        assert response.data['status'] == status.HTTP_400_BAD_REQUEST

    def test_login_invalid_email(self, api_client):
        """Test login with non-existent email."""
        payload = {"email": "nonexistent@example.com", "password": "password123"}
        encrypted_payload = encrypt_aes(AES_KEY, json.dumps(payload))
        response = api_client.post(
            reverse('login-list'),
            data={"data": encrypted_payload},
            format='json'
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data['message'] == "Invalid email or password"
        assert response.data['status'] == status.HTTP_400_BAD_REQUEST

    def test_login_invalid_password(self, api_client, user):
        """Test login with incorrect password."""
        payload = {"email": "test@example.com", "password": "wrongpassword"}
        encrypted_payload = encrypt_aes(AES_KEY, json.dumps(payload))
        response = api_client.post(
            reverse('login-list'),
            data={"data": encrypted_payload},
            format='json'
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data['message'] == "Invalid email or password"
        assert response.data['status'] == status.HTTP_400_BAD_REQUEST
        user.refresh_from_db()
        assert user.failed_login_attempts == 1
        assert user.last_failed_login is not None

    def test_login_blocked_user(self, api_client, user):
        """Test login for a blocked user."""
        user.failed_login_attempts = 5
        user.last_failed_login = timezone.now()
        user.save()
        payload = {"email": "test@example.com", "password": "password123"}
        encrypted_payload = encrypt_aes(AES_KEY, json.dumps(payload))
        response = api_client.post(
            reverse('login-list'),
            data={"data": encrypted_payload},
            format='json'
        )
        assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS
        assert response.data['message'] == "User is blocked due to multiple failed login attempts"
        assert response.data['status'] == status.HTTP_429_TOO_MANY_REQUESTS
        user.refresh_from_db()
        assert user.failed_login_attempts == 5  # Unchanged
        assert user.last_failed_login is not None

    def test_login_block_expired(self, api_client, user):
        """Test login after block duration expires."""
        user.failed_login_attempts = 5
        user.last_failed_login = timezone.now() - timedelta(minutes=6)
        user.save()
        payload = {"email": "test@example.com", "password": "password123"}
        encrypted_payload = encrypt_aes(AES_KEY, json.dumps(payload))
        with patch('users.views.generate_jwt_tokens', return_value=("access_token_123", "refresh_token_123")):
            response = api_client.post(
                reverse('login-list'),
                data={"data": encrypted_payload},
                format='json'
            )
        assert response.status_code == status.HTTP_200_OK
        assert response.data['message'] == "Login successful"
        assert response.data['status'] == status.HTTP_200_OK
        user.refresh_from_db()
        assert user.failed_login_attempts == 0
        assert user.last_failed_login is None