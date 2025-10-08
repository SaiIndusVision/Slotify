import os
from django.conf import settings
from django.contrib import admin
from django.urls import path, include, re_path
from django.views.generic import TemplateView
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from django.conf.urls.static import static
from django.views.static import serve as static_serve

BASE_DIR = settings.BASE_DIR
schema_view = get_schema_view(
    openapi.Info(
        title="Slotify API",
        default_version='v1',
        description="These are the APIs used for building the Slotify application.",
        terms_of_service="https://www.example.com/terms/",
        contact=openapi.Contact(email="saithimmareddy06@gmail.com"),
        license=openapi.License(name="Awesome License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
    # url="https://4x86tw12-8000.inc1.devtunnels.ms"
    
)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('users.urls')),
    path('api/', include('slots.urls')),
    path('api/refresh_token/', TokenRefreshView.as_view(), name='token_refresh'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
]

urlpatterns += [
    # Serve static Angular files (JS, CSS, etc.)
    re_path(r'^(?P<path>.*\.(js|css|ico|png|jpg|jpeg|svg))$', static_serve, {
        'document_root': os.path.join(BASE_DIR, 'frontend', 'dist'),
    }),

    # Fallback to index.html for Angular routes
    re_path(r'^.*$', TemplateView.as_view(template_name="index.html")),
]