from django.contrib import admin
from django.urls import path, include
from django.urls import re_path
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
    TokenBlacklistView,
)

from .views import CustomTokenObtainPairView, UserInfoView, CustomTokenVerifyView, CustomTokenBlacklistView

schema_view = get_schema_view(
   openapi.Info(
      title="Snippets API",
      default_version='v1',
      description="Test description",
      terms_of_service="https://www.google.com/policies/terms/",
      contact=openapi.Contact(email="contact@snippets.local"),
      license=openapi.License(name="BSD License"),
   ),
   public=True,
   permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
    path('swagger<format>/', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
    
    path('admin/', admin.site.urls),
    path('gateway/login/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'), 
    path('gateway/user_info/', UserInfoView.as_view(), name='optain_user_info'), 
    path('gateway/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),  
    path('gateway/token/verify/', TokenVerifyView.as_view(), name='token_verify'),  
    path('gateway/logout/', TokenBlacklistView.as_view(), name='token_blacklist'),

    path('gateway/api/', include('api_users.urls')),
]

