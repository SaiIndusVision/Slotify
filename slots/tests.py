import pytest
from django.urls import reverse
from rest_framework import status
from django.utils import timezone
from slots.models import Category, Slot, Booking
from users.models import User, Role
from rest_framework.test import APIClient
from django.contrib.auth.hashers import make_password
from datetime import datetime
from rest_framework_simplejwt.tokens import RefreshToken

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
        username="1234567890",
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

@pytest.fixture
def category(db, user):
    """Fixture to create a test category."""
    return Category.objects.create(
        name="Test Category",
        description="Test Description",
        is_active=True,
        created_by=user,
        updated_by=user,
        created_at=timezone.now(),
        updated_at=timezone.now()
    )

@pytest.fixture
def slot(db, category, user):
    """Fixture to create a test slot."""
    start_time = timezone.make_aware(datetime(2025, 10, 2, 10, 0))
    end_time = timezone.make_aware(datetime(2025, 10, 2, 11, 0))
    return Slot.objects.create(
        category=category,
        start_time=start_time,
        end_time=end_time,
        is_active=True,
        created_by=user,
        updated_by=user,
        created_at=timezone.now(),
        updated_at=timezone.now()
    )

@pytest.fixture
def booking(db, slot, user):
    """Fixture to create a test booking."""
    return Booking.objects.create(
        slot=slot,
        user=user,
        status="confirmed",
        created_at=timezone.now(),
        updated_at=timezone.now()
    )

@pytest.mark.django_db
class TestCategoryViewSet:
    """Test cases for CategoryViewSet CRUD operations."""

    def test_create_category_success(self, authenticated_client, user):
        """Test successful category creation."""
        data = {
            "name": "New Category",
            "description": "New Description",
            "is_active": True,
            "created_by": user.id
        }
        response = authenticated_client.post(reverse('category-list'), data, format='json')
        assert response.status_code == status.HTTP_201_CREATED
        assert response.data['message'] == "Category created successfully"
        assert Category.objects.filter(name="New Category").exists()

    def test_create_category_missing_name(self, authenticated_client, user):
        """Test category creation with missing name."""
        data = {
            "description": "New Description",
            "is_active": True,
            "created_by": user.id
        }
        response = authenticated_client.post(reverse('category-list'), data, format='json')
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data['message'] == "All fields are required"

    def test_create_category_invalid_created_by(self, authenticated_client):
        """Test category creation with invalid created_by ID."""
        data = {
            "name": "New Category",
            "description": "New Description",
            "is_active": True,
            "created_by": 999  # Non-existent user
        }
        response = authenticated_client.post(reverse('category-list'), data, format='json')
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert response.data['message'] == "User not found"

    def test_create_category_no_created_by(self, authenticated_client):
        """Test category creation without created_by."""
        data = {
            "name": "New Category",
            "description": "New Description",
            "is_active": True
        }
        response = authenticated_client.post(reverse('category-list'), data, format='json')
        assert response.status_code == status.HTTP_201_CREATED
        assert response.data['message'] == "Category created successfully"
        assert Category.objects.filter(name="New Category").exists()

    def test_list_categories(self, authenticated_client, category):
        """Test listing all categories with pagination."""
        response = authenticated_client.get(reverse('category-list'))
        assert response.status_code == status.HTTP_200_OK
        assert response.data['message'] == "Paginated categories fetched successfully"
        assert len(response.data['data']) == 1
        assert response.data['data'][0]['name'] == "Test Category"
        assert response.data['data'][0]['description'] == "Test Description"

    def test_list_categories_empty(self, authenticated_client):
        """Test listing categories when no categories exist."""
        response = authenticated_client.get(reverse('category-list'))
        assert response.status_code == status.HTTP_200_OK
        assert response.data['message'] == "Paginated categories fetched successfully"
        assert len(response.data['data']) == 0

    def test_retrieve_category_success(self, authenticated_client, category, user):
        """Test retrieving a category by ID."""
        response = authenticated_client.get(reverse('category-detail', kwargs={'pk': category.id}))
        assert response.status_code == status.HTTP_200_OK
        assert response.data['message'] == "Category fetched successfully"
        assert response.data['data']['name'] == "Test Category"
        assert response.data['data']['description'] == "Test Description"
        assert response.data['data']['created_by'] == user.id

    def test_retrieve_category_not_found(self, authenticated_client):
        """Test retrieving a non-existent category."""
        response = authenticated_client.get(reverse('category-detail', kwargs={'pk': 999}))
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert response.data['message'] == "Category not found"

    def test_update_category_success(self, authenticated_client, category, user):
        """Test updating a category's details."""
        data = {
            "name": "Updated Category",
            "description": "Updated Description",
            "is_active": False,
            "updated_by": user.id
        }
        response = authenticated_client.put(reverse('category-detail', kwargs={'pk': category.id}), data, format='json')
        assert response.status_code == status.HTTP_200_OK
        assert response.data['message'] == "Category updated successfully"
        category.refresh_from_db()
        assert category.name == "Updated Category"
        assert category.description == "Updated Description"
        assert category.is_active is False
        assert category.updated_by.id == user.id

    def test_update_category_partial(self, authenticated_client, category):
        """Test partially updating a category's details."""
        data = {
            "name": "Partially Updated Category"
        }
        response = authenticated_client.put(reverse('category-detail', kwargs={'pk': category.id}), data, format='json')
        assert response.status_code == status.HTTP_200_OK
        assert response.data['message'] == "Category updated successfully"
        category.refresh_from_db()
        assert category.name == "Partially Updated Category"
        assert category.description == "Test Description"  # Unchanged
        assert category.is_active is True  # Unchanged

    def test_update_category_invalid_updated_by(self, authenticated_client, category):
        """Test updating a category with invalid updated_by ID."""
        data = {
            "name": "Updated Category",
            "updated_by": 999  # Non-existent user
        }
        response = authenticated_client.put(reverse('category-detail', kwargs={'pk': category.id}), data, format='json')
        assert response.status_code == status.HTTP_200_OK
        assert response.data['message'] == "Category updated successfully"
        category.refresh_from_db()
        assert category.name == "Updated Category"
        assert category.updated_by is None  # Set to None due to invalid ID

    def test_update_category_not_found(self, authenticated_client):
        """Test updating a non-existent category."""
        data = {
            "name": "Non-existent Category"
        }
        response = authenticated_client.put(reverse('category-detail', kwargs={'pk': 999}), data, format='json')
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert response.data['message'] == "Category not found"

    def test_delete_category_success(self, authenticated_client, category):
        """Test deleting a category (hard delete)."""
        response = authenticated_client.delete(reverse('category-detail', kwargs={'pk': category.id}))
        assert response.status_code == status.HTTP_200_OK
        assert response.data['message'] == "Category deleted successfully"
        assert not Category.objects.filter(pk=category.id).exists()

    def test_delete_category_not_found(self, authenticated_client):
        """Test deleting a non-existent category."""
        response = authenticated_client.delete(reverse('category-detail', kwargs={'pk': 999}))
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert response.data['message'] == "Category not found"

@pytest.mark.django_db
class TestSlotViewSet:
    """Test cases for SlotViewSet CRUD operations."""

    def test_create_slot_success(self, api_client, category, user):
        """Test successful slot creation (authenticated)."""
        api_client.force_authenticate(user=user)
        data = {
            "category": category.id,
            "start_time": "2025-10-02T10:00:00Z",
            "end_time": "2025-10-02T11:00:00Z",
            "is_active": True
        }
        response = api_client.post(reverse('slot-list'), data, format='json')
        assert response.status_code == status.HTTP_201_CREATED
        assert response.data['message'] == "Slot created successfully"
        expected_start = timezone.make_aware(datetime(2025, 10, 2, 10, 0))
        expected_end = timezone.make_aware(datetime(2025, 10, 2, 11, 0))
        assert Slot.objects.filter(
            category=category,
            start_time=expected_start,
            end_time=expected_end,
            created_by=user
        ).exists()
        slot_data = response.data['data']
        assert str(slot_data['start_time']) == "2025-10-02 10:00:00+00:00"
        assert str(slot_data['end_time']) == "2025-10-02 11:00:00+00:00"
        assert slot_data['is_active'] is True

    def test_create_slot_missing_fields(self, authenticated_client, user):
        """Test slot creation with missing required fields."""
        data = {
            "category": 1,  # Missing start_time and end_time
            "is_active": True
        }
        response = authenticated_client.post(reverse('slot-list'), data, format='json')
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data['message'] == "All fields are required"

    def test_create_slot_invalid_category(self, authenticated_client, user):
        """Test slot creation with invalid category ID."""
        data = {
            "category": 999,  # Non-existent category
            "start_time": "2025-10-02T10:00:00Z",
            "end_time": "2025-10-02T11:00:00Z",
            "is_active": True
        }
        response = authenticated_client.post(reverse('slot-list'), data, format='json')
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert response.data['message'] == "Category not found"

    def test_create_slot_unauthenticated(self, api_client, category):
        """Test slot creation without authentication (should fail due to IsAuthenticated)."""
        data = {
            "category": category.id,
            "start_time": "2025-10-02T10:00:00Z",
            "end_time": "2025-10-02T11:00:00Z",
            "is_active": True
        }
        response = api_client.post(reverse('slot-list'), data, format='json')
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert not Slot.objects.filter(category=category).exists()

    def test_create_slot_invalid_datetime(self, api_client, category, user):
        """Test slot creation with invalid datetime format."""
        api_client.force_authenticate(user=user)
        data = {
            "category": category.id,
            "start_time": "invalid-datetime",
            "end_time": "2025-10-02T11:00:00Z",
            "is_active": True
        }
        response = api_client.post(reverse('slot-list'), data, format='json')
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data['message'] == "Invalid datetime format. Use ISO 8601 format (e.g. 2025-09-12T12:30:21Z)."

    def test_create_slot_invalid_time(self, authenticated_client, category, user):
        """Test slot creation with start_time >= end_time."""
        data = {
            "category": category.id,
            "start_time": "2025-10-02T11:00:00Z",
            "end_time": "2025-10-02T10:00:00Z",  # End time before start time
            "is_active": True
        }
        response = authenticated_client.post(reverse('slot-list'), data, format='json')
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data['message'] == "End time must be greater than start time"

    def test_create_slot_overlap(self, authenticated_client, category, user):
        """Test slot creation with overlapping slot."""
        existing_start = timezone.make_aware(datetime(2025, 10, 2, 10, 0))
        existing_end = timezone.make_aware(datetime(2025, 10, 2, 11, 0))
        Slot.objects.create(
            category=category,
            start_time=existing_start,
            end_time=existing_end,
            is_active=True,
            created_by=user
        )
        data = {
            "category": category.id,
            "start_time": "2025-10-02T10:30:00Z",  # Overlaps with existing slot
            "end_time": "2025-10-02T11:30:00Z",
            "is_active": True
        }
        response = authenticated_client.post(reverse('slot-list'), data, format='json')
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data['message'] == "Slot overlaps with an existing slot in the same category"

    def test_list_slots(self, authenticated_client, slot):
        """Test listing all slots with pagination."""
        response = authenticated_client.get(reverse('slot-list'))
        assert response.status_code == status.HTTP_200_OK
        assert response.data['message'] == "Slot list fetched successfully"
        assert len(response.data['data']) == 1
        assert response.data['data'][0]['category_id'] == slot.category.id
        assert response.data['data'][0]['is_active'] is True
        assert str(response.data['data'][0]['start_time']) == "2025-10-02 10:00:00+00:00"
        assert str(response.data['data'][0]['end_time']) == "2025-10-02 11:00:00+00:00"

    def test_list_slots_empty(self, authenticated_client):
        """Test listing slots when no slots exist."""
        response = authenticated_client.get(reverse('slot-list'))
        assert response.status_code == status.HTTP_200_OK
        assert response.data['message'] == "Slot list fetched successfully"
        assert len(response.data['data']) == 0

    def test_list_slots_filter_by_category(self, authenticated_client, slot):
        """Test filtering slots by category."""
        response = authenticated_client.get(reverse('slot-list'), {'category': slot.category.id})
        assert response.status_code == status.HTTP_200_OK
        assert response.data['message'] == "Slot list fetched successfully"
        assert len(response.data['data']) == 1
        assert response.data['data'][0]['category_id'] == slot.category.id

    def test_list_slots_filter_by_is_active(self, authenticated_client, slot, category):
        """Test filtering slots by is_active (true)."""
        response = authenticated_client.get(reverse('slot-list'), {'is_active': 'true'})
        assert response.status_code == status.HTTP_200_OK
        assert response.data['message'] == "Slot list fetched successfully"
        assert len(response.data['data']) == 1
        assert response.data['data'][0]['is_active'] is True

    def test_list_slots_filter_by_is_active_false(self, authenticated_client, category):
        """Test filtering slots by is_active (false)."""
        inactive_start = timezone.make_aware(datetime(2025, 10, 2, 12, 0))
        inactive_end = timezone.make_aware(datetime(2025, 10, 2, 13, 0))
        inactive_slot = Slot.objects.create(
            category=category,
            start_time=inactive_start,
            end_time=inactive_end,
            is_active=False
        )
        response = authenticated_client.get(reverse('slot-list'), {'is_active': 'false'})
        assert response.status_code == status.HTTP_200_OK
        assert response.data['message'] == "Slot list fetched successfully"
        assert len(response.data['data']) == 1
        assert response.data['data'][0]['is_active'] is False
        inactive_slot.delete()

    def test_list_slots_invalid_page_size(self, authenticated_client):
        """Test listing slots with invalid page_size."""
        response = authenticated_client.get(reverse('slot-list'), {'page_size': 'invalid'})
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data['message'] == "Invalid page_size"

    def test_retrieve_slot_success(self, authenticated_client, slot):
        """Test retrieving a slot by ID."""
        response = authenticated_client.get(reverse('slot-detail', kwargs={'pk': slot.id}))
        assert response.status_code == status.HTTP_200_OK
        assert response.data['message'] == "Slot fetched successfully"
        assert response.data['data']['category_id'] == slot.category.id
        assert response.data['data']['is_active'] is True
        assert str(response.data['data']['start_time']) == "2025-10-02 10:00:00+00:00"
        assert str(response.data['data']['end_time']) == "2025-10-02 11:00:00+00:00"

    def test_retrieve_slot_not_found(self, authenticated_client):
        """Test retrieving a non-existent slot."""
        response = authenticated_client.get(reverse('slot-detail', kwargs={'pk': 999}))
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert response.data['message'] == "Slot not found"

    def test_update_slot_success(self, api_client, slot, user, category):
        """Test updating a slot's details (authenticated)."""
        api_client.force_authenticate(user=user)
        data = {
            "category": category.id,
            "start_time": "2025-10-02T12:00:00Z",
            "end_time": "2025-10-02T13:00:00Z",
            "is_active": False
        }
        response = api_client.put(reverse('slot-detail', kwargs={'pk': slot.id}), data, format='json')
        assert response.status_code == status.HTTP_200_OK
        assert response.data['message'] == "Slot updated successfully"
        slot.refresh_from_db()
        assert slot.category.id == category.id
        expected_start = timezone.make_aware(datetime(2025, 10, 2, 12, 0))
        expected_end = timezone.make_aware(datetime(2025, 10, 2, 13, 0))
        assert slot.start_time == expected_start
        assert slot.end_time == expected_end
        assert slot.is_active is False
        assert slot.updated_by == user
        assert str(response.data['data']['start_time']) == "2025-10-02 12:00:00+00:00"
        assert str(response.data['data']['end_time']) == "2025-10-02 13:00:00+00:00"

    def test_update_slot_partial(self, authenticated_client, slot):
        """Test partially updating a slot's details."""
        data = {
            "start_time": "2025-10-02T09:00:00Z"  # Before slot.end_time
        }
        response = authenticated_client.put(reverse('slot-detail', kwargs={'pk': slot.id}), data, format='json')
        assert response.status_code == status.HTTP_200_OK
        assert response.data['message'] == "Slot updated successfully"
        slot.refresh_from_db()
        expected_start = timezone.make_aware(datetime(2025, 10, 2, 9, 0))
        assert slot.start_time == expected_start
        assert slot.is_active is True  # Unchanged
        assert str(response.data['data']['start_time']) == "2025-10-02 09:00:00+00:00"

    def test_update_slot_invalid_datetime(self, api_client, slot, user):
        """Test updating a slot with invalid datetime format."""
        api_client.force_authenticate(user=user)
        data = {
            "start_time": "invalid-datetime"
        }
        response = api_client.put(reverse('slot-detail', kwargs={'pk': slot.id}), data, format='json')
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data['message'] == "Invalid datetime format. Use ISO 8601 format (e.g. 2025-09-12T12:30:21Z)."

    def test_update_slot_invalid_time(self, authenticated_client, slot, user):
        """Test updating a slot with start_time >= end_time."""
        data = {
            "start_time": "2025-10-02T12:00:00Z",
            "end_time": "2025-10-02T11:00:00Z"  # End time before start time
        }
        response = authenticated_client.put(reverse('slot-detail', kwargs={'pk': slot.id}), data, format='json')
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data['message'] == "End time must be greater than start time"

    def test_update_slot_overlap(self, authenticated_client, slot, user, category):
        """Test updating a slot to overlap with another slot."""
        overlap_start = timezone.make_aware(datetime(2025, 10, 2, 12, 0))
        overlap_end = timezone.make_aware(datetime(2025, 10, 2, 13, 0))
        Slot.objects.create(
            category=category,
            start_time=overlap_start,
            end_time=overlap_end,
            is_active=True,
            created_by=user
        )
        data = {
            "category": category.id,
            "start_time": "2025-10-02T12:30:00Z",  # Overlaps with existing slot
            "end_time": "2025-10-02T13:30:00Z",
            "is_active": True
        }
        response = authenticated_client.put(reverse('slot-detail', kwargs={'pk': slot.id}), data, format='json')
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data['message'] == "Slot overlaps with an existing slot in the same category"

    def test_update_slot_invalid_category(self, authenticated_client, slot, user):
        """Test updating a slot with invalid category ID."""
        data = {
            "category": 999,  # Non-existent category
            "start_time": "2025-10-02T12:00:00Z"
        }
        response = authenticated_client.put(reverse('slot-detail', kwargs={'pk': slot.id}), data, format='json')
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert response.data['message'] == "Category not found"

    def test_update_slot_not_found(self, authenticated_client, category):
        """Test updating a non-existent slot."""
        data = {
            "category": category.id,
            "start_time": "2025-10-02T12:00:00Z",
            "end_time": "2025-10-02T13:00:00Z"
        }
        response = authenticated_client.put(reverse('slot-detail', kwargs={'pk': 999}), data, format='json')
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert response.data['message'] == "Slot not found"

    def test_delete_slot_success(self, authenticated_client, slot):
        """Test deleting a slot (hard delete)."""
        response = authenticated_client.delete(reverse('slot-detail', kwargs={'pk': slot.id}))
        assert response.status_code == status.HTTP_200_OK
        assert response.data['message'] == "Slot deleted successfully"
        assert not Slot.objects.filter(pk=slot.id).exists()

    def test_delete_slot_not_found(self, authenticated_client):
        """Test deleting a non-existent slot."""
        response = authenticated_client.delete(reverse('slot-detail', kwargs={'pk': 999}))
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert response.data['message'] == "Slot not found"

@pytest.mark.django_db
class TestBookingViewSet:
    """Test cases for BookingViewSet CRUD operations."""

    def test_create_booking_success(self, authenticated_client, slot, user):
        """Test successful booking creation."""
        data = {
            "slot": slot.id,
            "user": user.id
        }
        response = authenticated_client.post(reverse('booking-list'), data, format='json')
        assert response.status_code == status.HTTP_201_CREATED
        assert response.data['message'] == "Booking created successfully"
        assert Booking.objects.filter(slot=slot, user=user).exists()
        assert response.data['data']['slot'] == slot.id
        assert response.data['data']['user'] == user.id
        assert response.data['data']['status'] == "booked"

    def test_create_booking_missing_fields(self, authenticated_client):
        """Test booking creation with missing required fields."""
        data = {
            "slot": 1  # Missing user
        }
        response = authenticated_client.post(reverse('booking-list'), data, format='json')
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data['message'] == "All fields are required"

    def test_create_booking_invalid_slot(self, authenticated_client, user):
        """Test booking creation with invalid slot ID."""
        data = {
            "slot": 999,  # Non-existent slot
            "user": user.id
        }
        response = authenticated_client.post(reverse('booking-list'), data, format='json')
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert response.data['message'] == "Slot not found"

    def test_create_booking_invalid_user(self, authenticated_client, slot):
        """Test booking creation with invalid user ID."""
        data = {
            "slot": slot.id,
            "user": 999  # Non-existent user
        }
        response = authenticated_client.post(reverse('booking-list'), data, format='json')
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert response.data['message'] == "User not found"

    def test_create_booking_slot_already_booked(self, authenticated_client, booking, user):
        """Test booking creation for an already booked slot."""
        data = {
            "slot": booking.slot.id,
            "user": user.id
        }
        response = authenticated_client.post(reverse('booking-list'), data, format='json')
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data['message'] == "This slot is already booked by another user"

    def test_list_bookings(self, authenticated_client, booking):
        """Test listing all bookings with pagination."""
        response = authenticated_client.get(reverse('booking-list'))
        assert response.status_code == status.HTTP_200_OK
        assert response.data['message'] == "Booking list fetched successfully"
        assert len(response.data['data']) == 1
        assert response.data['data'][0]['slot'] == booking.slot.id
        assert response.data['data'][0]['user'] == booking.user.id
        assert response.data['data'][0]['status'] == "confirmed"

    def test_list_bookings_empty(self, authenticated_client):
        """Test listing bookings when no bookings exist."""
        response = authenticated_client.get(reverse('booking-list'))
        assert response.status_code == status.HTTP_200_OK
        assert response.data['message'] == "Booking list fetched successfully"
        assert len(response.data['data']) == 0

    def test_list_bookings_invalid_page_size(self, authenticated_client):
        """Test listing bookings with invalid page_size."""
        response = authenticated_client.get(reverse('booking-list'), {'page_size': 'invalid'})
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data['message'] == "Invalid page_size"

    def test_retrieve_booking_success(self, authenticated_client, booking):
        """Test retrieving a booking by ID."""
        response = authenticated_client.get(reverse('booking-detail', kwargs={'pk': booking.id}))
        assert response.status_code == status.HTTP_200_OK
        assert response.data['message'] == "Booking fetched successfully"
        assert response.data['data']['slot'] == booking.slot.id
        assert response.data['data']['user'] == booking.user.id
        assert response.data['data']['status'] == "confirmed"

    def test_retrieve_booking_not_found(self, authenticated_client):
        """Test retrieving a non-existent booking."""
        response = authenticated_client.get(reverse('booking-detail', kwargs={'pk': 999}))
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert response.data['message'] == "Booking not found"

    def test_update_booking_success(self, authenticated_client, booking, slot, user):
        """Test updating a booking's details."""
        new_slot = Slot.objects.create(
            category=slot.category,
            start_time=timezone.make_aware(datetime(2025, 10, 2, 12, 0)),
            end_time=timezone.make_aware(datetime(2025, 10, 2, 13, 0)),
            is_active=True,
            created_by=user,
            updated_by=user,
            created_at=timezone.now(),
            updated_at=timezone.now()
        )
        data = {
            "slot": new_slot.id,
            "status": "cancelled"
        }
        response = authenticated_client.put(reverse('booking-detail', kwargs={'pk': booking.id}), data, format='json')
        assert response.status_code == status.HTTP_200_OK
        assert response.data['message'] == "Booking updated successfully"
        booking.refresh_from_db()
        assert booking.slot.id == new_slot.id
        assert booking.status == "cancelled"
        assert response.data['data']['slot'] == new_slot.id
        assert response.data['data']['status'] == "cancelled"

    def test_update_booking_partial(self, authenticated_client, booking):
        """Test partially updating a booking's status."""
        data = {
            "status": "cancelled"
        }
        response = authenticated_client.put(reverse('booking-detail', kwargs={'pk': booking.id}), data, format='json')
        assert response.status_code == status.HTTP_200_OK
        assert response.data['message'] == "Booking updated successfully"
        booking.refresh_from_db()
        assert booking.status == "cancelled"
        assert response.data['data']['slot'] == booking.slot.id  # Unchanged
        assert response.data['data']['status'] == "cancelled"

    def test_update_booking_invalid_slot(self, authenticated_client, booking):
        """Test updating a booking with invalid slot ID."""
        data = {
            "slot": 999  # Non-existent slot
        }
        response = authenticated_client.put(reverse('booking-detail', kwargs={'pk': booking.id}), data, format='json')
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert response.data['message'] == "Slot not found"

    def test_update_booking_slot_already_booked(self, authenticated_client, booking, slot, user):
        """Test updating a booking to a slot that is already booked."""
        other_slot = Slot.objects.create(
            category=slot.category,
            start_time=timezone.make_aware(datetime(2025, 10, 2, 12, 0)),
            end_time=timezone.make_aware(datetime(2025, 10, 2, 13, 0)),
            is_active=True,
            created_by=user,
            updated_by=user,
            created_at=timezone.now(),
            updated_at=timezone.now()
        )
        Booking.objects.create(
            slot=other_slot,
            user=user,
            status="confirmed",
            created_at=timezone.now(),
            updated_at=timezone.now()
        )
        data = {
            "slot": other_slot.id
        }
        response = authenticated_client.put(reverse('booking-detail', kwargs={'pk': booking.id}), data, format='json')
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data['message'] == "This slot is already booked by another user"

    def test_update_booking_not_found(self, authenticated_client, slot):
        """Test updating a non-existent booking."""
        data = {
            "slot": slot.id,
            "status": "cancelled"
        }
        response = authenticated_client.put(reverse('booking-detail', kwargs={'pk': 999}), data, format='json')
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert response.data['message'] == "Booking not found"

    def test_delete_booking_success(self, authenticated_client, booking):
        """Test deleting a booking."""
        response = authenticated_client.delete(reverse('booking-detail', kwargs={'pk': booking.id}))
        assert response.status_code == status.HTTP_200_OK
        assert response.data['message'] == "Booking deleted successfully"
        assert not Booking.objects.filter(pk=booking.id).exists()

    def test_delete_booking_not_found(self, authenticated_client):
        """Test deleting a non-existent booking."""
        response = authenticated_client.delete(reverse('booking-detail', kwargs={'pk': 999}))
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert response.data['message'] == "Booking not found"

@pytest.mark.django_db
class TestDashboardViewSet:
    """Test cases for DashboardViewSet."""

    @pytest.mark.django_db

    def test_dashboard_with_data(self, authenticated_client, category, slot, booking, user):
        """Test dashboard endpoint with existing data."""
        response = authenticated_client.get(reverse('dashboard-list'))
        assert response.status_code == status.HTTP_200_OK
        assert response.data['message'] == "Dashboard data fetched successfully"
        assert response.data['status'] == status.HTTP_200_OK
        assert response.data['data']['summary'] == {
            "total_categories": 1,
            "active_categories": 1,
            "inactive_categories": 0,
            "total_slots": 1,
            "active_slots": 1,
            "inactive_slots": 0,
            "total_bookings": 1,
            "booked_slots": 0,  # Booking status is "confirmed", not "booked"
            "cancelled_bookings": 0,
            "total_users": 1,
        }
        assert len(response.data['data']['recent_categories']) == 1
        category_data = response.data['data']['recent_categories'][0]
        assert category_data['id'] == category.id
        assert category_data['name'] == "Test Category"
        assert category_data['description'] == "Test Description"
        assert category_data['is_active'] is True
        assert category_data['created_by_id'] == user.id
        assert category_data['created_by_name'] == "Test User"
        assert len(response.data['data']['recent_slots']) == 1
        slot_data = response.data['data']['recent_slots'][0]
        assert slot_data['id'] == slot.id
        assert slot_data['category_id'] == category.id
        assert slot_data['category_name'] == "Test Category"
        assert slot_data['is_active'] is True
        assert slot_data['created_by_id'] == user.id
        assert slot_data['created_by_name'] == "Test User"
        assert str(slot_data['start_time']) == "2025-10-02 10:00:00+00:00"
        assert str(slot_data['end_time']) == "2025-10-02 11:00:00+00:00"
        assert len(response.data['data']['recent_bookings']) == 1
        booking_data = response.data['data']['recent_bookings'][0]
        assert booking_data['id'] == booking.id
        assert booking_data['slot_id'] == slot.id
        assert booking_data['user_id'] == user.id
        assert booking_data['user_name'] == "Test User"
        assert booking_data['status'] == "confirmed"
        assert booking_data['slot_time'] == f"{slot.start_time} - {slot.end_time}"

    def test_dashboard_with_multiple_records(self, authenticated_client, user, category):
        """Test dashboard with multiple categories, slots, and bookings."""
        category2 = Category.objects.create(
            name="Category 2",
            description="Another Category",
            is_active=False,
            created_by=user,
            updated_by=user,
            created_at=timezone.now(),
            updated_at=timezone.now()
        )
        slot1 = Slot.objects.create(
            category=category,
            start_time=timezone.make_aware(datetime(2025, 10, 2, 10, 0)),
            end_time=timezone.make_aware(datetime(2025, 10, 2, 11, 0)),
            is_active=True,
            created_by=user,
            updated_by=user,
            created_at=timezone.now(),
            updated_at=timezone.now()
        )
        slot2 = Slot.objects.create(
            category=category2,
            start_time=timezone.make_aware(datetime(2025, 10, 2, 12, 0)),
            end_time=timezone.make_aware(datetime(2025, 10, 2, 13, 0)),
            is_active=False,
            created_by=user,
            updated_by=user,
            created_at=timezone.now(),
            updated_at=timezone.now()
        )
        booking1 = Booking.objects.create(
            slot=slot1,
            user=user,
            status="booked",
            created_at=timezone.now(),
            updated_at=timezone.now()
        )
        booking2 = Booking.objects.create(
            slot=slot2,
            user=user,
            status="cancelled",
            created_at=timezone.now(),
            updated_at=timezone.now()
        )
        response = authenticated_client.get(reverse('dashboard-list'))
        assert response.status_code == status.HTTP_200_OK
        assert response.data['message'] == "Dashboard data fetched successfully"
        assert response.data['status'] == status.HTTP_200_OK
        assert response.data['data']['summary'] == {
            "total_categories": 2,
            "active_categories": 1,
            "inactive_categories": 1,
            "total_slots": 2,
            "active_slots": 1,
            "inactive_slots": 1,
            "total_bookings": 2,
            "booked_slots": 1,
            "cancelled_bookings": 1,
            "total_users": 1,
        }
        assert len(response.data['data']['recent_categories']) == 2
        assert response.data['data']['recent_categories'][0]['name'] == "Category 2"
        assert response.data['data']['recent_categories'][1]['name'] == "Test Category"
        assert len(response.data['data']['recent_slots']) == 2
        assert response.data['data']['recent_slots'][0]['category_name'] == "Category 2"
        assert response.data['data']['recent_slots'][1]['category_name'] == "Test Category"
        assert len(response.data['data']['recent_bookings']) == 2
        assert response.data['data']['recent_bookings'][0]['status'] == "cancelled"
        assert response.data['data']['recent_bookings'][1]['status'] == "booked"