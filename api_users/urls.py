from django.urls import path, include
from .views import UserView, PermissionAPIView, RoleAPIView, ApplicationAPIView, AssignPermissionToUserAPIView, AssignRoleToUserAPIView, AssignPermissionToRoleAPIView, AssignPermissionToApplicationAPIView
from rest_framework.routers import DefaultRouter


# Configuration routeur configuration
router = DefaultRouter()
router.register(r'users', UserView, basename='user')

urlpatterns = [
    path('', include(router.urls), name='crud_user'),
    path('permission/', PermissionAPIView.as_view()),
    path('permission/<uuid:pk>/', PermissionAPIView.as_view()),
    path('role/', RoleAPIView.as_view()),
    path('role/<uuid:pk>/', RoleAPIView.as_view()),
    path('application/', ApplicationAPIView.as_view()),
    path('application/<uuid:pk>/', ApplicationAPIView.as_view()),
    path('assign_role_user/', AssignRoleToUserAPIView.as_view()),
    path('assign_role_user/<uuid:pk>/', AssignRoleToUserAPIView.as_view()),
    path('assign_permission_user/', AssignPermissionToUserAPIView.as_view()),
    path('assign_permission_user/<uuid:pk>/', AssignPermissionToUserAPIView.as_view()),
    path('assign_permission_role/', AssignPermissionToRoleAPIView.as_view()),
    path('assign_permission_role/<uuid:pk>/', AssignPermissionToRoleAPIView.as_view()),
    path('assign_permission_application/', AssignPermissionToApplicationAPIView.as_view()),
    path('assign_permission_application/<uuid:pk>/', AssignPermissionToApplicationAPIView.as_view()),
]
