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
    path('user/', UserView.as_view()),
    path('user/<uuid:pk>/', UserView.as_view()),
    path('user/search/', SearchUserView.as_view()),
    path("set_password/", SetPasswordAPIView.as_view(), name="set_password"),
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
    path("email_reset_password/", EmailToResetPasswordAPIView.as_view(), name="email_reset_password"),
    # path("email_change_password/", EmailToChangePasswordAPIView.as_view(), name="email_change_password"),
    path("change_password/", ChangePasswordAPIView.as_view()),
]
