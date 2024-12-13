"""
URL configuration for api_gateway_settings project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
    TokenBlacklistView,
)

from .views import CustomTokenObtainPairView, UserInfoView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api_gateway/token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'), 
    path('api_gateway/user_info/', UserInfoView.as_view(), name='optain_user_info'), 
    path('api_gateway/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),  
    path('api_gateway/token/verify/', TokenVerifyView.as_view(), name='token_verify'),  
    path('api_gateway/token/revoke/', TokenBlacklistView.as_view(), name='token_blacklist'),

    path('api_gateway/api_users/', include('api_users.urls')),
]
