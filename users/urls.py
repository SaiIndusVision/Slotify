from django.urls import path,include
from .views import *
from rest_framework.routers import DefaultRouter

router = DefaultRouter()
router.register('signup',SignUpViewSet,basename='signup')
router.register(r'users', UserViewSet, basename='user')
router.register('reset_password', ResetPasswordViewSet, basename='reset_password')
router.register('validate-token', ValidateResetTokenViewSet, basename='validate_token')
router.register('login', LoginViewSet, basename='login')
router.register('role',RoleViewSet,basename='role')
urlpatterns = [
    path('', include(router.urls)),
]