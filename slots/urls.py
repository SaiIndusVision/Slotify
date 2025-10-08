from django.urls import path,include
from .views import *
from rest_framework.routers import DefaultRouter

router = DefaultRouter()
router.register('categories', CategoryViewSet, basename='category')
router.register('slots', SlotViewSet, basename='slot')
router.register('bookings', BookingViewSet, basename='booking') 
router.register('dashboard', DashboardViewSet, basename='dashboard')
urlpatterns = [
    path('', include(router.urls)),
]       
