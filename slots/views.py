from rest_framework import viewsets, status
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from django.utils import timezone
from .models import Category,Slot,Booking
from users.models import User
from utils.helpers import format_response, get_user, MESSAGES, STATUS_CODES
from utils.custompagination import CustomPagination
from django.utils.dateparse import parse_date
from django.db.models import Q
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated

class CategoryViewSet(viewsets.ViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    """
    ViewSet for managing categories (CRUD operations)
    """

    @swagger_auto_schema(
        operation_summary="Create Category",
        operation_description="Create a new category",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['name'],
            properties={
                'name': openapi.Schema(type=openapi.TYPE_STRING, description='Category name'),
                'description': openapi.Schema(type=openapi.TYPE_STRING, description='Category description'),
                'is_active': openapi.Schema(type=openapi.TYPE_BOOLEAN, description='Is category active'),
                'created_by': openapi.Schema(type=openapi.TYPE_INTEGER, description='User ID who creates this category')
            }
        ),
        responses={
            201: openapi.Response(description="Category created successfully"),
            400: openapi.Response(description="Bad request"),
        }
    )
    def create(self, request):
        data = request.data
        name = data.get('name')
        description = data.get('description')
        is_active = data.get('is_active', True)
        created_by_id = data.get('created_by')

        if not name:
            return format_response(MESSAGES["all_fields_required"], status_code=STATUS_CODES["bad_request"])

        created_by = get_user(created_by_id)
        if created_by is None and created_by_id is not None:
            return format_response(MESSAGES["user_not_found"], status_code=STATUS_CODES["not_found"])

        Category.objects.create(
            name=name,
            description=description,
            is_active=is_active,
            created_by=created_by,
        )

        return format_response(
            MESSAGES['category_created'],
            status_code=STATUS_CODES["success_created"]
        )

    @swagger_auto_schema(
        operation_summary="List Categories",
        operation_description="Fetch a paginated list of categories with optional filters. "
                              "Available filters: `name`, `is_active`, `created_by`, `from_date`, `to_date`. "
                              "Supports query parameters `page` and `page_size`.",
        manual_parameters=[
            openapi.Parameter('page', openapi.IN_QUERY, description="Page number", type=openapi.TYPE_INTEGER, default=1),
            openapi.Parameter('page_size', openapi.IN_QUERY, description="Number of items per page", type=openapi.TYPE_INTEGER, default=10),
            openapi.Parameter('name', openapi.IN_QUERY, description="Filter by category name (partial match)", type=openapi.TYPE_STRING),
            openapi.Parameter('is_active', openapi.IN_QUERY, description="Filter by active status (true/false)", type=openapi.TYPE_BOOLEAN),
            openapi.Parameter('created_by', openapi.IN_QUERY, description="Filter by creator (user id)", type=openapi.TYPE_INTEGER),
            openapi.Parameter('from_date', openapi.IN_QUERY, description="Filter categories created on/after this date (YYYY-MM-DD)", type=openapi.TYPE_STRING, format="date"),
            openapi.Parameter('to_date', openapi.IN_QUERY, description="Filter categories created on/before this date (YYYY-MM-DD)", type=openapi.TYPE_STRING, format="date"),
        ],
        responses={200: openapi.Response(description="Paginated list of categories")}
    )
    def list(self, request):
        categories = Category.objects.all().order_by("-id")

        # --- Filters ---
        name = request.query_params.get("name")
        is_active = request.query_params.get("is_active")
        created_by = request.query_params.get("created_by")
        from_date = request.query_params.get("from_date")
        to_date = request.query_params.get("to_date")

        if name:
            categories = categories.filter(name__icontains=name)

        if is_active is not None:
            if is_active.lower() in ["true", "1"]:
                categories = categories.filter(is_active=True)
            elif is_active.lower() in ["false", "0"]:
                categories = categories.filter(is_active=False)

        if created_by:
            categories = categories.filter(created_by_id=created_by)

        if from_date:
            from_date_parsed = parse_date(from_date)
            if from_date_parsed:
                categories = categories.filter(created_at__date__gte=from_date_parsed)

        if to_date:
            to_date_parsed = parse_date(to_date)
            if to_date_parsed:
                categories = categories.filter(created_at__date__lte=to_date_parsed)

        # --- Pagination ---
        paginator = CustomPagination()
        page_size = request.query_params.get("page_size")
        if page_size:
            try:
                paginator.page_size = int(page_size)
            except ValueError:
                return format_response("Invalid page_size", status_code=STATUS_CODES["bad_request"])

        paginated_categories = paginator.paginate_queryset(categories, request)

        # data = [
        #     {
        #         "id": c.id,
        #         "name": c.name,
        #         "description": c.description,
        #         "is_active": c.is_active,
        #         "created_by": c.created_by.id if c.created_by else None,
        #         "updated_by": c.updated_by.id if c.updated_by else None,
        #         "created_at": c.created_at,
        #         "updated_at": c.updated_at
        #     }
        #     for c in paginated_categories
        # ]
        data = [
            {
                "id": c.id,
                "name": c.name,
                "description": c.description,
                "is_active": c.is_active,
                "created_by_id": c.created_by.id if c.created_by else None,
                "created_by_name": c.created_by.name if c.created_by and c.created_by.name else None,
                "updated_by_id": c.updated_by.id if c.updated_by else None,
                "updated_by_name": c.updated_by.name if c.updated_by and c.updated_by.name else None,
                "created_at": c.created_at,
                "updated_at": c.updated_at
            }
            for c in paginated_categories
        ]


        response = paginator.get_paginated_response(data)
        response.data["status"] = STATUS_CODES["success_ok"]
        response.data["message"] = "Paginated categories fetched successfully"
        return response


    @swagger_auto_schema(
        operation_summary="Retrieve Category",
        operation_description="Retrieve a single category by ID",
        responses={200: "Category details", 404: "Category not found"}
    )
    def retrieve(self, request, pk=None):
        try:
            category = Category.objects.get(pk=pk)
        except Category.DoesNotExist:
            return format_response(MESSAGES['category_not_found'], status_code=STATUS_CODES["not_found"])

        data = {
            "id": category.id,
            "name": category.name,
            "description": category.description,
            "is_active": category.is_active,
            "created_by": category.created_by.id if category.created_by else None,
            "updated_by": category.updated_by.id if category.updated_by else None,
            "created_at": category.created_at,
            "updated_at": category.updated_at
        }

        return format_response(MESSAGES['category_retrieved'], data=data, status_code=STATUS_CODES["success_ok"])

    @swagger_auto_schema(
        operation_summary="Update Category",
        operation_description="Update category details",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'name': openapi.Schema(type=openapi.TYPE_STRING),
                'description': openapi.Schema(type=openapi.TYPE_STRING),
                'is_active': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                'updated_by': openapi.Schema(type=openapi.TYPE_INTEGER, description='User ID who updates this category')
            }
        ),
        responses={200: "Category updated successfully", 404: "Category not found"}
    )
    def update(self, request, pk=None):
        try:
            category = Category.objects.get(pk=pk)
        except Category.DoesNotExist:
            return format_response(MESSAGES.get("category_not_found", "Category not found"), status_code=STATUS_CODES["not_found"])

        data = request.data
        category.name = data.get('name', category.name)
        category.description = data.get('description', category.description)
        category.is_active = data.get('is_active', category.is_active)

        updated_by_id = data.get('updated_by')
        category.updated_by = get_user(updated_by_id) if updated_by_id else category.updated_by

        category.updated_at = timezone.now()
        category.save()

        return format_response(
            MESSAGES['category_updated'],
            status_code=STATUS_CODES["success_ok"]
        )

    @swagger_auto_schema(
        operation_summary="Delete Category",
        operation_description="Soft delete a category by marking it inactive",
        responses={200: "Category deleted successfully", 404: "Category not found"}
    )
    def destroy(self, request, pk=None):
        try:
            category = Category.objects.get(pk=pk)
        except Category.DoesNotExist:
            return format_response(MESSAGES.get("category_not_found", "Category not found"), status_code=STATUS_CODES["not_found"])
        category.delete()
        # category.is_active = False
        # category.updated_at = timezone.now()
        # category.save()

        return format_response(
            MESSAGES['category_deleted'],
            status_code=STATUS_CODES["success_ok"]
        )


class SlotViewSet(viewsets.ViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    """
    ViewSet for Slot Management
    """

    # ---------------- CREATE ----------------
    @swagger_auto_schema(
        operation_summary="Create Slot",
        operation_description="Create a new slot with category, start_time, and end_time. "
                            "Ensures no overlapping slots exist within the same category.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["category", "start_time", "end_time"],
            properties={
                "category": openapi.Schema(type=openapi.TYPE_INTEGER, description="Category ID"),
                "start_time": openapi.Schema(type=openapi.TYPE_STRING, format="date-time", description="Slot start time"),
                "end_time": openapi.Schema(type=openapi.TYPE_STRING, format="date-time", description="Slot end time"),
                "is_active": openapi.Schema(type=openapi.TYPE_BOOLEAN, description="Active status (default: True)"),
            }
        ),
        responses={201: MESSAGES["slot_created"], 400: "Invalid request / Slot overlap error"}
    )
    def create(self, request):
        category_id = request.data.get("category")
        start_time = request.data.get("start_time")
        end_time = request.data.get("end_time")
        is_active = request.data.get("is_active", True)

        if not category_id or not start_time or not end_time:
            return format_response(
                MESSAGES["all_fields_required"],
                status_code=STATUS_CODES["bad_request"]
            )

        category = Category.objects.filter(id=category_id).first()
        if not category:
            return format_response(
                MESSAGES['category_not_found'],
                status_code=STATUS_CODES["not_found"]
            )

        # Convert to datetime
        from django.utils.dateparse import parse_datetime
        start_time = parse_datetime(start_time)
        end_time = parse_datetime(end_time)

        if not start_time or not end_time:
            return format_response(
                MESSAGES["slot_invalid_datetime"],
                status_code=STATUS_CODES["bad_request"]
            )

        if start_time >= end_time:
            return format_response(
                MESSAGES["slot_invalid_time"],
                status_code=STATUS_CODES["bad_request"]
            )

        # Check for overlapping slots
        overlapping_slot = Slot.objects.filter(
            category=category,
            start_time__lt=end_time,
            end_time__gt=start_time
        ).first()

        if overlapping_slot:
            return format_response(
                MESSAGES["slot_overlap"],
                status_code=STATUS_CODES["bad_request"]
            )

        # Create slot
        slot = Slot.objects.create(
            category=category,
            start_time=start_time,
            end_time=end_time,
            is_active=is_active,
            created_by=request.user if request.user.is_authenticated else None
        )

        data = {
            "id": slot.id,
            "start_time": slot.start_time,
            "end_time": slot.end_time,
            "is_active": slot.is_active,
        }
        return format_response(
            MESSAGES["slot_created"],
            data=data,
            status_code=STATUS_CODES["success_created"]
        )



    # ---------------- LIST ----------------
    @swagger_auto_schema(
        operation_summary="List Slots",
        operation_description="Fetch paginated list of slots. Supports filters: category, is_active",
        manual_parameters=[
            openapi.Parameter("page", openapi.IN_QUERY, type=openapi.TYPE_INTEGER, description="Page number"),
            openapi.Parameter("page_size", openapi.IN_QUERY, type=openapi.TYPE_INTEGER, description="Items per page"),
            openapi.Parameter("category", openapi.IN_QUERY, type=openapi.TYPE_INTEGER, description="Filter by Category ID"),
            openapi.Parameter("is_active", openapi.IN_QUERY, type=openapi.TYPE_BOOLEAN, description="Filter by active status"),
        ],
        responses={200: MESSAGES["slot_list"]}
    )
    def list(self, request):
        slots = Slot.objects.select_related('category', 'created_by', 'updated_by').all().order_by("-id")

        category = request.query_params.get("category")
        is_active = request.query_params.get("is_active")

        if category:
            slots = slots.filter(category_id=category)
        if is_active is not None:
            slots = slots.filter(is_active=is_active.lower() in ["true", "1"])

        paginator = CustomPagination()
        page_size = request.query_params.get("page_size")
        if page_size:
            try:
                paginator.page_size = int(page_size)
            except ValueError:
                return format_response("Invalid page_size", status_code=STATUS_CODES["bad_request"])

        paginated_slots = paginator.paginate_queryset(slots, request)
        data = [
            {
                "id": s.id,
                "category_id": s.category.id if s.category else None,
                "category_name": s.category.name if s.category else None,
                "start_time": s.start_time,
                "end_time": s.end_time,
                "is_active": s.is_active,
                "created_by_id": s.created_by.id if s.created_by else None,
                "created_by_name": s.created_by.get_full_name() if s.created_by else None,
                "updated_by_id": s.updated_by.id if s.updated_by else None,
                "updated_by_name": s.updated_by.get_full_name() if s.updated_by else None,
            }
            for s in paginated_slots
        ]

        response = paginator.get_paginated_response(data)
        response.data["status"] = STATUS_CODES["success_ok"]
        response.data["message"] = MESSAGES["slot_list"]
        return response

    # ---------------- RETRIEVE ----------------
    @swagger_auto_schema(
        operation_summary="Retrieve Slot",
        operation_description="Fetch details of a specific slot by ID",
        responses={200: MESSAGES["slot_retrieved"], 404: MESSAGES["slot_not_found"]}
    )
    def retrieve(self, request, pk=None):
        slot = Slot.objects.select_related('category', 'created_by', 'updated_by').filter(pk=pk).first()
        if not slot:
            return format_response(MESSAGES["slot_not_found"], status_code=STATUS_CODES["not_found"])

        data = {
            "id": slot.id,
            "category_id": slot.category.id if slot.category else None,
            "category_name": slot.category.name if slot.category else None,
            "start_time": slot.start_time,
            "end_time": slot.end_time,
            "is_active": slot.is_active,
            "created_by_id": slot.created_by.id if slot.created_by else None,
            "created_by_name": slot.created_by.get_full_name() if slot.created_by else None,
            "updated_by_id": slot.updated_by.id if slot.updated_by else None,
            "updated_by_name": slot.updated_by.get_full_name() if slot.updated_by else None,
        }
        return format_response(MESSAGES["slot_retrieved"], data=data)


    # ---------------- UPDATE ----------------
    @swagger_auto_schema(
        operation_summary="Update Slot",
        operation_description="Update slot details by ID. Ensures no overlapping slots exist within the same category.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "category": openapi.Schema(type=openapi.TYPE_INTEGER, description="Category ID"),
                "start_time": openapi.Schema(type=openapi.TYPE_STRING, format="date-time", description="Slot start time"),
                "end_time": openapi.Schema(type=openapi.TYPE_STRING, format="date-time", description="Slot end time"),
                "is_active": openapi.Schema(type=openapi.TYPE_BOOLEAN, description="Active status"),
            }
        ),
        responses={
            200: MESSAGES["slot_updated"],
            404: MESSAGES["slot_not_found"],
            400: "Invalid request / Slot overlap error"
        }
    )
    def update(self, request, pk=None):
        slot = Slot.objects.filter(pk=pk).first()
        if not slot:
            return format_response(MESSAGES["slot_not_found"], status_code=STATUS_CODES["not_found"])

        # Update category if provided
        category_id = request.data.get("category")
        if category_id:
            category = Category.objects.filter(id=category_id).first()
            if not category:
                return format_response(MESSAGES["category_not_found"], status_code=STATUS_CODES["not_found"])
            slot.category = category

        # Parse start_time and end_time
        from django.utils.dateparse import parse_datetime
        start_time = parse_datetime(request.data.get("start_time")) if request.data.get("start_time") else slot.start_time
        end_time = parse_datetime(request.data.get("end_time")) if request.data.get("end_time") else slot.end_time

        if not start_time or not end_time:
            return format_response(MESSAGES["slot_invalid_datetime"], status_code=STATUS_CODES["bad_request"])

        if start_time >= end_time:
            return format_response(MESSAGES["slot_invalid_time"], status_code=STATUS_CODES["bad_request"])

        # Check overlapping slots for the same category (exclude current slot)
        overlapping_slot = Slot.objects.filter(
            category=slot.category,
            start_time__lt=end_time,
            end_time__gt=start_time
        ).exclude(id=slot.id).first()

        if overlapping_slot:
            return format_response(MESSAGES["slot_overlap"], status_code=STATUS_CODES["bad_request"])

        # Update fields
        slot.start_time = start_time
        slot.end_time = end_time
        slot.is_active = request.data.get("is_active", slot.is_active)
        slot.updated_by = request.user if request.user.is_authenticated else None
        slot.save()

        data = {
            "id": slot.id,
            "category": slot.category.id if slot.category else None,
            "start_time": slot.start_time,
            "end_time": slot.end_time,
            "is_active": slot.is_active,
        }
        return format_response(MESSAGES["slot_updated"], data=data, status_code=STATUS_CODES["success_ok"])

    # ---------------- DELETE ----------------
    @swagger_auto_schema(
        operation_summary="Delete Slot",
        operation_description="Delete slot by ID",
        responses={200: MESSAGES["slot_deleted"], 404: MESSAGES["slot_not_found"]}
    )
    def destroy(self, request, pk=None):
        slot = Slot.objects.filter(pk=pk).first()
        if not slot:
            return format_response(MESSAGES["slot_not_found"], status_code=STATUS_CODES["not_found"])

        slot.delete()
        return format_response(MESSAGES["slot_deleted"], status_code=STATUS_CODES["success_ok"])
    
    

class BookingViewSet(viewsets.ViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    """
    ViewSet for managing bookings: create, list, retrieve, update, delete
    """

    @swagger_auto_schema(
        operation_summary="Create Booking",
        operation_description="Create a booking for a slot. Prevents double booking for the same slot.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["slot", "user"],
            properties={
                "slot": openapi.Schema(type=openapi.TYPE_INTEGER, description="Slot ID"),
                "user": openapi.Schema(type=openapi.TYPE_INTEGER, description="User ID")
            }
        ),
        responses={201: MESSAGES["booking_created"], 400: MESSAGES["slot_already_booked"]}
    )
    def create(self, request):
        slot_id = request.data.get("slot")
        user_id = request.data.get("user")

        if not slot_id or not user_id:
            return format_response(MESSAGES["all_fields_required"], status_code=STATUS_CODES["bad_request"])

        slot = Slot.objects.filter(id=slot_id).first()
        user = User.objects.filter(id=user_id).first()

        if not slot:
            return format_response(MESSAGES["slot_not_found"], status_code=STATUS_CODES["not_found"])
        if not user:
            return format_response(MESSAGES["user_not_found"], status_code=STATUS_CODES["not_found"])

        # Check if slot is already booked
        if Booking.objects.filter(slot=slot).exists():
            return format_response(MESSAGES["slot_already_booked"], status_code=STATUS_CODES["bad_request"])

        booking = Booking.objects.create(
            slot=slot,
            user=user
        )

        data = {
            "id": booking.id,
            "slot": booking.slot.id,
            "user": booking.user.id,
            "status": booking.status,
            "created_at": booking.created_at,
            "updated_at": booking.updated_at,
        }
        return format_response(MESSAGES["booking_created"], data=data, status_code=STATUS_CODES["success_created"])

    @swagger_auto_schema(
        operation_summary="List Bookings",
        operation_description="Fetch a paginated list of bookings. Supports filters: slot_id, user_id, status, from_date, to_date, and pagination: page, page_size.",
        manual_parameters=[
            openapi.Parameter('slot_id', openapi.IN_QUERY, type=openapi.TYPE_INTEGER, description="Filter by Slot ID"),
            openapi.Parameter('user_id', openapi.IN_QUERY, type=openapi.TYPE_INTEGER, description="Filter by User ID"),
            openapi.Parameter('status', openapi.IN_QUERY, type=openapi.TYPE_STRING, description="Filter by booking status"),
            openapi.Parameter('from_date', openapi.IN_QUERY, type=openapi.TYPE_STRING, format='date-time', description="Filter bookings from this date"),
            openapi.Parameter('to_date', openapi.IN_QUERY, type=openapi.TYPE_STRING, format='date-time', description="Filter bookings up to this date"),
            openapi.Parameter('page', openapi.IN_QUERY, type=openapi.TYPE_INTEGER, description="Page number", default=1),
            openapi.Parameter('page_size', openapi.IN_QUERY, type=openapi.TYPE_INTEGER, description="Page size", default=10),
        ],
        responses={200: MESSAGES["booking_list"]}
    )
    def list(self, request):
        bookings = Booking.objects.all().select_related('slot__category').order_by("-id")
        
        # Filters
        slot_id = request.query_params.get("slot_id")
        user_id = request.query_params.get("user_id")
        status_param = request.query_params.get("status")
        from_date = request.query_params.get("from_date")
        to_date = request.query_params.get("to_date")

        if slot_id:
            bookings = bookings.filter(slot_id=slot_id)
        if user_id:
            bookings = bookings.filter(user_id=user_id)
        if status_param:
            bookings = bookings.filter(status__iexact=status_param)
        if from_date:
            bookings = bookings.filter(created_at__gte=from_date)
        if to_date:
            bookings = bookings.filter(created_at__lte=to_date)

        # Pagination
        paginator = CustomPagination()
        page_size = request.query_params.get('page_size')
        if page_size:
            try:
                paginator.page_size = int(page_size)
            except ValueError:
                return format_response("Invalid page_size", status_code=STATUS_CODES["bad_request"])

        paginated_bookings = paginator.paginate_queryset(bookings, request)

        data = [
            {
                "id": b.id,
                "slot": b.slot.id,
                "user": b.user.id,
                "status": b.status,
                "start_time": b.slot.start_time,
                "end_time": b.slot.end_time,
                "category_name": b.slot.category.name,
                "created_at": b.created_at,
                "updated_at": b.updated_at
            }
            for b in paginated_bookings
        ]

        response = paginator.get_paginated_response(data)
        response.data["status"] = STATUS_CODES["success_ok"]
        response.data["message"] = MESSAGES["booking_list"]
        return response

    @swagger_auto_schema(
        operation_summary="Retrieve Booking",
        operation_description="Retrieve details of a booking by ID",
        responses={200: MESSAGES["booking_retrieved"], 404: MESSAGES["booking_not_found"]}
    )
    def retrieve(self, request, pk=None):
        booking = Booking.objects.filter(pk=pk).select_related('slot__category').first()
        if not booking:
            return format_response(MESSAGES["booking_not_found"], status_code=STATUS_CODES["not_found"])

        data = {
            "id": booking.id,
            "slot": booking.slot.id,
            "user": booking.user.id,
            "status": booking.status,
            "start_time": booking.slot.start_time,
            "end_time": booking.slot.end_time,
            "category_name": booking.slot.category.name,
            "created_at": booking.created_at,
            "updated_at": booking.updated_at,
        }
        return format_response(MESSAGES["booking_retrieved"], data=data, status_code=STATUS_CODES["success_ok"])

    @swagger_auto_schema(
        operation_summary="Update Booking",
        operation_description="Update booking details. Cannot change slot if already booked by another user.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "slot": openapi.Schema(type=openapi.TYPE_INTEGER, description="Slot ID"),
                "status": openapi.Schema(type=openapi.TYPE_STRING, description="Booking status"),
            }
        ),
        responses={200: MESSAGES["booking_updated"], 404: MESSAGES["booking_not_found"], 400: MESSAGES["slot_already_booked"]}
    )
    def update(self, request, pk=None):
        booking = Booking.objects.filter(pk=pk).first()
        if not booking:
            return format_response(MESSAGES["booking_not_found"], status_code=STATUS_CODES["not_found"])

        slot_id = request.data.get("slot")
        if slot_id:
            slot = Slot.objects.filter(id=slot_id).first()
            if not slot:
                return format_response(MESSAGES["slot_not_found"], status_code=STATUS_CODES["not_found"])
            # Check slot double booking (exclude current booking)
            if Booking.objects.filter(slot=slot).exclude(id=booking.id).exists():
                return format_response(MESSAGES["slot_already_booked"], status_code=STATUS_CODES["bad_request"])
            booking.slot = slot

        booking.status = request.data.get("status", booking.status)
        booking.save()

        data = {
            "id": booking.id,
            "slot": booking.slot.id,
            "user": booking.user.id,
            "status": booking.status,
            "created_at": booking.created_at,
            "updated_at": booking.updated_at,
        }
        return format_response(MESSAGES["booking_updated"], data=data, status_code=STATUS_CODES["success_ok"])

    @swagger_auto_schema(
        operation_summary="Delete Booking",
        operation_description="Delete a booking by ID",
        responses={200: MESSAGES["booking_deleted"], 404: MESSAGES["booking_not_found"]}
    )
    def destroy(self, request, pk=None):
        booking = Booking.objects.filter(pk=pk).first()
        if not booking:
            return format_response(MESSAGES["booking_not_found"], status_code=STATUS_CODES["not_found"])
        booking.delete()
        return format_response(MESSAGES["booking_deleted"], status_code=STATUS_CODES["success_ok"])
    
    
class DashboardViewSet(viewsets.ViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    """
    Dashboard API ViewSet
    Provides summary counts and recent activity for dashboard display
    """

    @swagger_auto_schema(
        operation_summary="Dashboard Overview",
        operation_description="Fetch dashboard summary with counts and recent activity. "
                              "Includes categories, slots, bookings, and users.",
        responses={200: "Dashboard data fetched successfully"}
    )
    def list(self, request):
        # --- Summary Stats ---
        total_categories = Category.objects.count()
        active_categories = Category.objects.filter(is_active=True).count()
        inactive_categories = total_categories - active_categories

        total_slots = Slot.objects.count()
        active_slots = Slot.objects.filter(is_active=True).count()
        inactive_slots = total_slots - active_slots

        total_bookings = Booking.objects.count()
        booked_slots = Booking.objects.filter(status="booked").count()
        cancelled_bookings = Booking.objects.filter(status="cancelled").count()

        total_users = User.objects.count()

        summary = {
            "total_categories": total_categories,
            "active_categories": active_categories,
            "inactive_categories": inactive_categories,
            "total_slots": total_slots,
            "active_slots": active_slots,
            "inactive_slots": inactive_slots,
            "total_bookings": total_bookings,
            "booked_slots": booked_slots,
            "cancelled_bookings": cancelled_bookings,
            "total_users": total_users,
        }

        # --- Recent Bookings ---
        recent_bookings = Booking.objects.select_related("slot", "user").order_by("-created_at")[:5]
        recent_bookings_data = [
            {
                "id": b.id,
                "slot_id": b.slot.id if b.slot else None,
                "slot_time": f"{b.slot.start_time} - {b.slot.end_time}" if b.slot else None,
                "user_id": b.user.id if b.user else None,
                "user_name": b.user.name if b.user and b.user.name else b.user.username if b.user else None,
                "status": b.status,
                "created_at": b.created_at,
            }
            for b in recent_bookings
        ]

        # --- Recent Slots ---
        recent_slots = Slot.objects.select_related("category", "created_by").order_by("-created_at")[:5]
        recent_slots_data = [
            {
                "id": s.id,
                "category_id": s.category.id if s.category else None,
                "category_name": s.category.name if s.category else None,
                "start_time": s.start_time,
                "end_time": s.end_time,
                "is_active": s.is_active,
                "created_by_id": s.created_by.id if s.created_by else None,
                "created_by_name": s.created_by.name if s.created_by else None,
            }
            for s in recent_slots
        ]

        # --- Recent Categories ---
        recent_categories = Category.objects.select_related("created_by").order_by("-created_at")[:5]
        recent_categories_data = [
            {
                "id": c.id,
                "name": c.name,
                "description": c.description,
                "is_active": c.is_active,
                "created_by_id": c.created_by.id if c.created_by else None,
                "created_by_name": c.created_by.name if c.created_by else None,
                "created_at": c.created_at,
            }
            for c in recent_categories
        ]

        data = {
            "summary": summary,
            "recent_bookings": recent_bookings_data,
            "recent_slots": recent_slots_data,
            "recent_categories": recent_categories_data,
        }

        return format_response(
            message="Dashboard data fetched successfully",
            data=data,
            status_code=STATUS_CODES["success_ok"]
        )