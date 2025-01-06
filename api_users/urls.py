from django.urls import path, include
from .views import (
    UserView, 
    PermissionAPIView, 
    RoleAPIView,
    ApplicationAPIView,
    AssignPermissionToUserAPIView, 
    AssignRoleToUserAPIView, 
    AssignPermissionToRoleAPIView, 
    AssignPermissionToApplicationAPIView,
    SetPasswordAPIView,
    SearchUserView,
    EmailToResetPasswordAPIView,
    ChangePasswordAPIView
)

urlpatterns = [
    path('users/', UserView.as_view()),
    path('users/<uuid:pk>/', UserView.as_view()),
    path('users/search/', SearchUserView.as_view()),
    path("users/set_password/", SetPasswordAPIView.as_view(), name="set_password"),
    path("users/<uuid:pk>/change_password/", ChangePasswordAPIView.as_view()),
    path("email_reset_password/", EmailToResetPasswordAPIView.as_view(), name="email_reset_password"),
    path('permissions/', PermissionAPIView.as_view()),
    path('permissions/<uuid:pk>/', PermissionAPIView.as_view()),
    path('roles/', RoleAPIView.as_view()),
    path('roles/<uuid:pk>/', RoleAPIView.as_view()),
    path('applications/', ApplicationAPIView.as_view()),
    path('applications/<uuid:pk>/', ApplicationAPIView.as_view()),
    path('assign_role_user/', AssignRoleToUserAPIView.as_view()),
    path('assign_role_user/<uuid:pk>/', AssignRoleToUserAPIView.as_view()),
    path('grant_permission_user/', AssignPermissionToUserAPIView.as_view()),
    path('grant_permission_user/<uuid:pk>/', AssignPermissionToUserAPIView.as_view()),
    path('grant_permission_role/', AssignPermissionToRoleAPIView.as_view()),
    path('grant_permission_role/<uuid:pk>/', AssignPermissionToRoleAPIView.as_view()),
    path('grant_permission_application/', AssignPermissionToApplicationAPIView.as_view()),
    path('grant_permission_application/<uuid:pk>/', AssignPermissionToApplicationAPIView.as_view()),
]
