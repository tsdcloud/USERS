from .models import ( 
    CustomUser, 
    Permission, 
    Role, 
    Application, 
    AssignPermissionToUser, 
    AssignRoleToUser, 
    AssignPermissionToRole, 
    AssignPermissionApplication )

from .serializers import (
    UserSerializer, 
    PermissionSerializer, 
    ApplicationSerializer, 
    RoleSerializer, 
    AssignPermissionToUserSerializer, 
    AssignRoleToUserSerializer, 
    AssignPermissionToRoleSerializer, 
    AssignPermissionToApplicationSerializer, 
    UserDetailSerializer,
    UserWithPermissionsSerializer,
    UserWithRolesSerializer,
    ApplicationWithPermissionSerializer,
    AssignPermissionsToRoleSerializer )

from rest_framework.views import APIView
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.response import Response
from django.contrib.auth.models import AnonymousUser
from rest_framework.pagination import PageNumberPagination
from django.utils.timezone import now, timedelta
from django.core.mail import send_mail
import uuid
from django.contrib.auth.hashers import make_password
from .utils import validate_password, generate_random_chain
from django.db.models import Q
from rest_framework.permissions import IsAuthenticated

from rest_framework import permissions
from rest_framework.permissions import BasePermission

BERP_FRONT_END_URL = "https://berp.bfcgroupsa.com"


class SizePagination(PageNumberPagination):
    page_size = 100  # default page size
    page_size_query_param = 'page_size'
    max_page_size = 1000

class IsAdminOrSuperAdmin(BasePermission):
    """
    Custom permission to authorize only admin or superadmin users.
    """
    def has_permission(self, request, view):
        return request.user.is_admin or request.user.is_superuser
    
class IsOwnerOrAdmin(permissions.BasePermission):
    """
    Personalized permissions that allow access only if the user
    is acting on his or her own data, or if he or she is an administrator or super-administrator.
    """

    def has_object_permission(self, request, view, obj):
        # Check if the user is an administrator or super administrator or admin
        if request.user.is_superuser or request.user.is_admin:
            return True
        
        # Check if the user is the owner of the object
        if isinstance(obj, CustomUser):
            return obj == request.user

        # If the object is not of type CustomUser (e.g. another model), 
        # you can add other conditions according to your model
        return False

class UserView(APIView):
    """
    API view to handle CRUD operations for user.
    """
    permission_classes = [IsOwnerOrAdmin, IsAuthenticated]

    def get(self, request, pk=None):
        """
        Handle GET requests.
        If `pk` is provided, fetch a single instance; otherwise, fetch all instances.
        """
        if pk:
            # instance = get_object_or_404(CustomUser.objects.filter(is_active=True), pk=pk)
            # if request.user.is_superuser == True or request.user.is_admin == True:
            instance = get_object_or_404(CustomUser, pk=pk)

            # Check permission
            self.check_object_permissions(request, instance)

            serializer = UserDetailSerializer(instance)
            return Response({"success": True, "data":serializer.data}, status=status.HTTP_200_OK)
        else:
            # instances = CustomUser.objects.filter(is_active=True)
            if request.user.is_superuser == True:
                instances = CustomUser.objects.all()
            elif request.user.is_admin == True:
                instances = CustomUser.objects.filter(is_active=True)
            else:
                return Response(
                    {"success": False, "error": "You do not have permission to view this data."},
                    status=status.HTTP_403_FORBIDDEN
                )
                
            # Check permission
            # self.check_object_permissions(request, instances)

            # Paginate the queryset
            paginator = SizePagination()
            paginated_queryset = paginator.paginate_queryset(instances, request)

            # Serialize the paginated data
            serializer = UserDetailSerializer(paginated_queryset, many=True)
            paginated_response = paginator.get_paginated_response(serializer.data)

            return Response(
                {
                    "success": True,
                    "data": paginated_response.data,
                },
                status=status.HTTP_200_OK
            )
        
    
    def patch(self, request, pk):
        """
        Handle PATCH requests for partially updating an instance.
        """
        instance = get_object_or_404(CustomUser, pk=pk)

        # Check permission
        self.check_object_permissions(request, instance)
        
        serializer = UserSerializer(instance, data=request.data, partial=True, context={'request': request})

        if serializer.is_valid():
            serializer.save(updated_by=request.user)
            return Response({"success": True, "data": serializer.data}, status=status.HTTP_200_OK)
        return Response({"success": False, "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
    

    def put(self, request, pk):
        """
        Handle PUT requests for fully updating an instance, excluding the password field.
        """
        instance = get_object_or_404(CustomUser, pk=pk)

        # Check permission
        self.check_object_permissions(request, instance)

        serializer = UserSerializer(instance, data=request.data)
        
        if serializer.is_valid():
            serializer.save(updated_by=request.user)
            return Response({"success": True, "data" :serializer.data}, status=status.HTTP_200_OK)
        
        return Response({"success": False, "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
    

    def post(self, request):

        if not (request.user.is_superuser or request.user.is_admin):
            return Response({"success": False, "error": "Only admin or super admin can create users."}, status=status.HTTP_403_FORBIDDEN)

        serialiser = UserSerializer(data=request.data)

        if serialiser.is_valid():
            serialiser.save(created_by=request.user, updated_by=request.user, is_active=False)
            return Response(
                {
                    "success": True,
                    "data": serialiser.data
                }, 
                status=status.HTTP_201_CREATED
            )
        else:
            return Response(
                {
                    "success": False,
                    "errors": serialiser.errors
                }, 
                status=status.HTTP_400_BAD_REQUEST
            )
    
    def delete(self, request, pk):
        """
        Handle DELETE requests for deleting an instance.
        """

        delete = request.query_params.get('delete')

        instance = get_object_or_404(CustomUser, pk=pk)

        serializer = UserSerializer(instance, data=request.data, partial=True)

        # Check permission
        self.check_object_permissions(request, instance)

        if not delete :
            if serializer.is_valid():
                serializer.save(is_active=False)
                return Response({"success": True, "message": "Instance deactivated successfully."}, status=status.HTTP_200_OK)
        elif request.user.is_admin or request.user.is_superuser:
            if serializer.is_valid():
                serializer.save(is_active=False)
            # instance.delete()
                return Response({"success": True, "message": "Instance deleted successfully."}, status=status.HTTP_200_OK)
        else:
            return Response({"success": False, "error": "Only admin can perform this action."}, status=status.HTTP_403_FORBIDDEN)


class SetPasswordAPIView(APIView):
    """
    API View to handle password setting using a reset token.
    """

    def patch(self, request, *args, **kwargs):
        data = request.data
        token = request.query_params.get('token')
        password = data.get("password")
        confirm_password = data.get("confirm_password")

        if not token or not password or not confirm_password :
            return Response({"success": False, "error": "Token, password and confirm_password are required."}, status=status.HTTP_400_BAD_REQUEST)
        
        if password != confirm_password :
            return Response({"success": False, "error": "the provided passwords are not equal !!"}, status=status.HTTP_400_BAD_REQUEST)

        user = CustomUser.objects.filter(reset_token=token).first()

        if not user:
            return Response({"success": False, "error": "expired token."}, status=status.HTTP_400_BAD_REQUEST)

        if user.reset_token_expire < now():
            return Response({"success": False, "error": "expired token."}, status=status.HTTP_400_BAD_REQUEST)

        # Set the password and activate the user
        password_errors = validate_password(password)

        if password_errors:
            return Response({"success": False, 'errors': password_errors}, status=status.HTTP_400_BAD_REQUEST)
        
        user.password = make_password(password)
        user.reset_token = None
        user.reset_token_expire = None
        user.is_active = True
        user.save()

        return Response({"success": True, "message": "Password set successfully. You can now log in."}, status=status.HTTP_200_OK)

class EmailToResetPasswordAPIView(APIView):
    """
    API View to get email to reset password.
    """

    # permission_classes = [IsOwnerOrAdmin, IsAuthenticated]

    def post(self, request):
        data = request.data
        email = data.get("email")

        if not email:
            return Response({"success" : False, "error": "E-mail is required !!"}, status=status.HTTP_400_BAD_REQUEST)

        # print(request.user.email)

        # Create a token to use to reset the password
        reset_token = str(uuid.uuid4())
        token_expiry = now() + timedelta(hours=24)

        user = CustomUser.objects.filter(email=email).first()

        if not user:
            return Response({"success": False, "error": "user with this email was not found or invalid email"}, status=status.HTTP_400_BAD_REQUEST)

        # Construct the reset URL 
        reset_url = f"{BERP_FRONT_END_URL}/confirmPassword/?token={reset_token}"
        # reset_url = f"{'http://127.0.0.1:8000/api_gateway/api/reset_password/'}?token={reset_token}"

        # Send email with the reset link
        send_mail(
            "Set Your Password",
            f"Hi {user.first_name},\nPlease click the link below to reset your password:\n{reset_url}",
            "no-reply@bfcgroupsa.com",
            [email],
            fail_silently=False,
            html_message=f"""
                <p>Hi {user.first_name},</p>
                <p>Please click the link below to reset your password:</p>
                <a href="{reset_url}">Set Your Password</a>
            """
        )

        user.reset_token = reset_token
        user.reset_token_expire = token_expiry
        user.save()

        return Response({"success": True, "message": "email sent succesfully, check your email and follow the instruction."}, status=status.HTTP_200_OK)

class ChangePasswordAPIView(APIView):
    """
    API View to change setting without using a token.
    """

    permission_classes = [IsOwnerOrAdmin, IsAuthenticated]

    def patch(self, request, *args, **kwargs):
        data = request.data
        password = data.get("password")
        confirm_password = data.get("confirm_password")

        email = request.user.email

        if not password or not confirm_password :
            return Response({"success": False, "error": "Password and confirm_password are required."}, status=status.HTTP_400_BAD_REQUEST)
        
        if password != confirm_password :
            return Response({"success": False, "error": "the provided passwords are not equal !!"}, status=status.HTTP_400_BAD_REQUEST)

        user = CustomUser.objects.filter(email=email).first()

        # Set the password and activate the user
        password_errors = validate_password(password)

        if password_errors:
            return Response({"success": False, 'errors': password_errors}, status=status.HTTP_400_BAD_REQUEST)
        
        user.password = make_password(password)
        user.save()

        return Response({"success": True, "message": "Password changed successfully."}, status=status.HTTP_200_OK)

class SearchUserView(APIView):
    """
    View to search for users based on query parameters.
    """

    permission_classes = [IsAuthenticated]
    
    def get(self, request):

        if not (request.user.is_superuser or request.user.is_admin):
            return Response({"success": False, "error": "Only admin or super admin can perform this action."}, status=status.HTTP_403_FORBIDDEN)

        query_params = request.query_params
        first_name = query_params.get('first_name', None)
        last_name = query_params.get('last_name', None)
        email = query_params.get('email', None)
        username = query_params.get('username', None)
        is_active = query_params.get('is_active', None)

        # Parameter-based dynamic filter
        filters = Q()
        if first_name:
            filters &= Q(first_name__icontains=first_name)
        if last_name:
            filters &= Q(last_name__icontains=last_name)
        if email:
            filters &= Q(email__icontains=email)
        if username:
            filters &= Q(username__icontains=username)
        if is_active:
            filters &= Q(is_active__icontains=is_active)

        paginator = SizePagination()
        users = CustomUser.objects.filter(filters)

        paginated_queryset = paginator.paginate_queryset(users, request)
        serializer = UserSerializer(paginated_queryset, many=True)
        paginated_response = paginator.get_paginated_response(serializer.data)

        # Return list of users found
        # return paginator.get_paginated_response(serializer.data)
        return Response(
            {
                "success": True,
                "data": paginated_response.data,
            },
            status=status.HTTP_200_OK
        )
    

class PermissionAPIView(APIView):
    """
    API view to handle CRUD operations for Permission.
    """

    permission_classes = [IsOwnerOrAdmin, IsAuthenticated]

    def get(self, request, pk=None):
        """
        Handle GET requests.
        If `pk` is provided, fetch a single instance; otherwise, fetch all instances.
        """
        if pk:
            instance = get_object_or_404(Permission.objects.filter(is_active=True), pk=pk)

            # Check permission
            if not (request.user.is_superuser or request.user.is_admin):
                return Response({"success": False, "error": "Only admin or super admin can perform this action."}, status=status.HTTP_403_FORBIDDEN)

            serializer = PermissionSerializer(instance)
            return Response({"success": True, "data": serializer.data}, status=status.HTTP_200_OK)
        
        elif request.user.is_superuser or request.user.is_admin:
            if request.user.is_superuser:
                instances = Permission.objects.filter()
            else:
                instances = Permission.objects.filter(is_active=True)
            
            # Check permission
            # if not (request.user.is_superuser or request.user.is_admin):
            #     return Response({"success": False, "error": "Only admin or super admin can perform this action."}, status=status.HTTP_403_FORBIDDEN)

            paginator = SizePagination()
            paginated_queryset = paginator.paginate_queryset(instances, request)
            serializer = PermissionSerializer(paginated_queryset, many=True)
            paginated_response = paginator.get_paginated_response(serializer.data)
        
            return Response({"success": True, "data": paginated_response.data}, status=status.HTTP_200_OK)
        else:
            try:
                user = request.user
                serializer = UserWithPermissionsSerializer(user)
                return Response(
                    {
                        "success": True,
                        "data": serializer.data
                    },
                    status=status.HTTP_200_OK
                )
            except Exception as e:
                return Response(
                    {
                        "success": False,
                        "error": str(e)
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
    def post(self, request):
        """
        Handle POST requests for creating a new instance.
        """
        serializer = PermissionSerializer(data=request.data)

        # Check permission
        if not (request.user.is_superuser or request.user.is_admin):
            return Response({"success": False, "error": "Only admin or super admin can create permissions."}, status=status.HTTP_403_FORBIDDEN)
        
        if serializer.is_valid():
            serializer.save(created_by=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        # Save with the authenticated user as the creator
        return Response({"success": False, "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, pk):
        """
        Handle PUT requests for updating an instance.
        """
        instance = get_object_or_404(Permission, pk=pk)

        # Check permission
        if not (request.user.is_superuser or request.user.is_admin):
            return Response({"success": False, "error": "Only admin or super admin can perform this action."}, status=status.HTTP_403_FORBIDDEN)

        serializer = PermissionSerializer(instance, data=request.data, partial=False)
        if serializer.is_valid():
            serializer.save(updated_by=request.user)
            return Response({"success": True, "data": serializer.data}, status=status.HTTP_200_OK)
        return Response({"success": False, "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, pk):
        """
        Handle PATCH requests for partially updating an instance.
        """
        instance = get_object_or_404(Permission, pk=pk)

        # Check permission
        if not (request.user.is_superuser or request.user.is_admin):
            return Response({"success": False, "error": "Only admin or super admin can perform this action."}, status=status.HTTP_403_FORBIDDEN)


        serializer = PermissionSerializer(instance, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save(updated_by=request.user)
            return Response({"success": True, "data": serializer.data}, status=status.HTTP_200_OK)
        return Response({"success": False, "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        """
        Handle DELETE requests for deleting an instance.
        """
        instance = get_object_or_404(Permission, pk=pk)

        # Check permission
        if not (request.user.is_superuser or request.user.is_admin):
            return Response({"success": False, "error": "Only admin or super admin can perform this action."}, status=status.HTTP_403_FORBIDDEN)

        serializer = PermissionSerializer(instance, data=request.data, partial=True)

        # instance.delete()
        if serializer.is_valid():
            serializer.save(is_active=False)
        return Response({"success": True, "message": "Permisison deactivated successfully."}, status=status.HTTP_200_OK)

class RoleAPIView(APIView):
    """
    API view to handle CRUD operations for Role.
    """
    permission_classes = [IsAuthenticated, IsOwnerOrAdmin]
    
    def get(self, request, pk=None):
        """
        Handle GET requests.
        If `pk` is provided, fetch a single instance; otherwise, fetch all instances.
        """
        if pk:
            instance = get_object_or_404(Role.objects.filter(is_active=True), pk=pk)

            # Check permission
            if not (request.user.is_superuser or request.user.is_admin):
                return Response({"success": False, "error": "Only admin or super admin can perform this action."}, status=status.HTTP_403_FORBIDDEN)


            serializer = RoleSerializer(instance)
            return Response({"success": True, "data": serializer.data}, status=status.HTTP_200_OK)
        
        elif request.user.is_superuser or request.user.is_admin:
            if request.user.is_superuser:
                instances = Role.objects.filter()
            else:
                instances = Role.objects.filter(is_active=True)
            
            # Check permission
            # if not (request.user.is_superuser or request.user.is_admin):
            #     return Response({"success": False, "error": "Only admin or super admin can perform this action."}, status=status.HTTP_403_FORBIDDEN)

            paginator = SizePagination()
            paginated_queryset = paginator.paginate_queryset(instances, request)
            serializer = RoleSerializer(paginated_queryset, many=True)
            paginated_response = paginator.get_paginated_response(serializer.data)

            return Response({"success": True, "data": paginated_response.data}, status=status.HTTP_200_OK)
        
            # instances = Role.objects.filter(is_active=True)
            # serializer = RoleSerializer(instances, many=True)
            # return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            try:
                user = request.user
                serializer = UserWithRolesSerializer(user)
                return Response(
                    {
                        "success": True,
                        "data": serializer.data
                    },
                    status=status.HTTP_200_OK
                )
            except Exception as e:
                return Response(
                    {
                        "success": False,
                        "error": str(e)
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
    def post(self, request):
        """
        Handle POST requests for creating a new instance.
        """
        serializer = RoleSerializer(data=request.data)

        # Check permission
        if not (request.user.is_superuser or request.user.is_admin):
            return Response({"success": False, "error": "Only admin or super admin can perform this action."}, status=status.HTTP_403_FORBIDDEN)

        if serializer.is_valid():
            serializer.save(created_by=request.user)
            return Response({"success": True, "data": serializer.data}, status=status.HTTP_201_CREATED)
        
        # Save with the authenticated user as the creator
        return Response({"success": False, "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, pk):
        """
        Handle PUT requests for updating an instance.
        """
        instance = get_object_or_404(Role, pk=pk)
        
        # Check permission
        if not (request.user.is_superuser or request.user.is_admin):
            return Response({"success": False, "error": "Only admin or super admin can perform this action."}, status=status.HTTP_403_FORBIDDEN)

        serializer = RoleSerializer(instance, data=request.data, partial=False)
        if serializer.is_valid():
            serializer.save(updated_by=request.user)
            return Response({"success": True, "data": serializer.data}, status=status.HTTP_200_OK)
        return Response({"success": False, "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, pk):
        """
        Handle PATCH requests for partially updating an instance.
        """
        instance = get_object_or_404(Role, pk=pk)

        # Check permission
        if not (request.user.is_superuser or request.user.is_admin):
            return Response({"success": False, "error": "Only admin or super admin can perform this action."}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = RoleSerializer(instance, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save(updated_by=request.user)
            return Response({"success": True, "data": serializer.data}, status=status.HTTP_200_OK)
        return Response({"success": False, "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        """
        Handle DELETE requests for deleting an instance.
        """
        instance = get_object_or_404(Role, pk=pk)

        # Check permission
        if not (request.user.is_superuser or request.user.is_admin):
            return Response({"success": False, "error": "Only admin or super admin can perform this action."}, status=status.HTTP_403_FORBIDDEN)

        serializer = RoleSerializer(instance, data=request.data, partial=True)
        # instance.delete()
        if serializer.is_valid():
            serializer.save(is_active=False)
        return Response({"success": True, "message": "Role deactivated successfully."}, status=status.HTTP_200_OK)

class ApplicationAPIView(APIView):
    """
    API view to handle CRUD operations for Application.
    """

    permission_classes = [IsAuthenticated, IsOwnerOrAdmin]
    
    def get(self, request, pk=None):
        """
        Handle GET requests.
        If `pk` is provided, fetch a single instance; otherwise, fetch all instances.
        """
        # Check permission
        if not (request.user.is_superuser or request.user.is_admin):
            return Response({"success": False, "error": "Only admin or super admin can perform this action."}, status=status.HTTP_403_FORBIDDEN)

        if pk:
            instance = get_object_or_404(Application.objects.filter(is_active=True), pk=pk)

            serializer = ApplicationWithPermissionSerializer(instance)
            return Response({"success": True, "data": serializer.data}, status=status.HTTP_200_OK)
        else:
            if request.user.is_superuser:
                instances = Application.objects.filter()
            else:
                instances = Application.objects.filter(is_active=True)

            paginator = SizePagination()
            paginated_queryset = paginator.paginate_queryset(instances, request)
            serializer = ApplicationWithPermissionSerializer(paginated_queryset, many=True)
            paginated_response = paginator.get_paginated_response(serializer.data)

            return Response({"success": True, "data": paginated_response.data}, status=status.HTTP_200_OK)
        
    def post(self, request):
        """
        Handle POST requests for creating a new instance.
        """
        serializer = ApplicationSerializer(data=request.data)

        # Check permission
        if not (request.user.is_superuser or request.user.is_admin):
            return Response({"success": False, "error": "Only admin or super admin can perform this action."}, status=status.HTTP_403_FORBIDDEN)

        if serializer.is_valid():
            serializer.save(created_by=request.user)
            return Response({"success": True, "data": serializer.data}, status=status.HTTP_201_CREATED)
        
        # Save with the authenticated user as the creator
        return Response({"success": False, "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, pk):
        """
        Handle PUT requests for updating an instance.
        """
        instance = get_object_or_404(Application, pk=pk)
        
        # Check permission
        if not (request.user.is_superuser or request.user.is_admin):
            return Response({"success": False, "error": "Only admin or super admin can perform this action."}, status=status.HTTP_403_FORBIDDEN)

        serializer = ApplicationSerializer(instance, data=request.data, partial=False)
        if serializer.is_valid():
            serializer.save(updated_by=request.user)
            return Response({"success": True, "data": serializer.data}, status=status.HTTP_200_OK)
        return Response({"success": False, "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, pk):
        """
        Handle PATCH requests for partially updating an instance.
        """
        instance = get_object_or_404(Application, pk=pk)

        # Check permission
        if not (request.user.is_superuser or request.user.is_admin):
            return Response({"success": False, "error": "Only admin or super admin can perform this action."}, status=status.HTTP_403_FORBIDDEN)

        
        serializer = ApplicationSerializer(instance, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save(updated_by=request.user)
            return Response({"success": True, "data": serializer.data}, status=status.HTTP_200_OK)
        return Response({"success": False, "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        """
        Handle DELETE requests for deleting an instance.
        """
        instance = get_object_or_404(Application, pk=pk)
        
        # Check permission
        if not (request.user.is_superuser or request.user.is_admin):
            return Response({"success": False, "error": "Only admin or super admin can perform this action."}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = ApplicationSerializer(instance, data=request.data, partial=True)
        # instance.delete()
        if serializer.is_valid():
            serializer.save(is_active=False)
        return Response({"success": True, "message": "Application deactivated successfully."}, status=status.HTTP_200_OK)

# API View for AssignPermissionToUser
class AssignPermissionToUserAPIView(APIView):
    """
    API endpoint to assign a specific permission to a user.
    Accepts POST and GET requests with data corresponding to the AssignPermissionToUser model.
    """
    
    permission_classes = [IsAuthenticated, IsOwnerOrAdmin]
    
    def post(self, request):
        serializer = AssignPermissionToUserSerializer(data=request.data)

        # Check permission
        if not (request.user.is_superuser or request.user.is_admin):
            return Response({"success": False, "error": "Only admin or super admin can perform this action."}, status=status.HTTP_403_FORBIDDEN)
        
        if serializer.is_valid():
            serializer.save(assigned_by=request.user)
            return Response({"success": True, "data": serializer.data}, status=status.HTTP_201_CREATED)
        return Response({"success": False, "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
    
    def get(self, request, pk=None):
        """
        Handle GET requests.
        If `pk` is provided, fetch a single instance; otherwise, fetch all instances.
        """
        # Check permission
        if not (request.user.is_superuser or request.user.is_admin):
            return Response({"success": False, "error": "Only admin or super admin can perform this action."}, status=status.HTTP_403_FORBIDDEN)

        if pk:
            instance = get_object_or_404(AssignPermissionToUser, pk=pk)

            serializer = AssignPermissionToUserSerializer(instance)
            return Response({"success": True, "data": serializer.data}, status=status.HTTP_200_OK)
        else:
            instances = AssignPermissionToUser.objects.all()

            paginator = SizePagination()
            paginated_queryset = paginator.paginate_queryset(instances, request)
            serializer = AssignPermissionToUserSerializer(paginated_queryset, many=True)
            paginated_response = paginator.get_paginated_response(serializer.data)

            return Response({"success": True, "data": paginated_response.data}, status=status.HTTP_200_OK)
    
    def delete(self, request, pk):
        """
        Handle DELETE requests for deleting an instance.
        """
        instance = get_object_or_404(AssignPermissionToUser, pk=pk)

        # Check permission
        if not (request.user.is_superuser or request.user.is_admin):
            return Response({"success": False, "error": "Only admin or super admin can perform this action."}, status=status.HTTP_403_FORBIDDEN)

        instance.delete()

        return Response({"success": True, "message": "Instance deleted successfully."}, status=status.HTTP_200_OK)

# API View for AssignRoleToUser
class AssignRoleToUserAPIView(APIView):
    """
    API endpoint to assign a specific role to a user.
    Accepts POST requests with data corresponding to the AssignRoleToUser model.
    """
    permission_classes = [IsAuthenticated, IsOwnerOrAdmin]
    
    def post(self, request):
        serializer = AssignRoleToUserSerializer(data=request.data)

        # Check permission
        if not (request.user.is_superuser or request.user.is_admin):
            return Response({"success": False, "error": "Only admin or super admin can perform this action."}, status=status.HTTP_403_FORBIDDEN)

        
        if serializer.is_valid():
            serializer.save(assigned_by=request.user)
            return Response({"success": True, "data": serializer.data}, status=status.HTTP_201_CREATED)
        return Response({"success": False, "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
    
    def get(self, request, pk=None):
        """
        Handle GET requests.
        If `pk` is provided, fetch a single instance; otherwise, fetch all instances.
        """
        # Check permission
        if not (request.user.is_superuser or request.user.is_admin):
            return Response({"success": False, "error": "Only admin or super admin can perform this action."}, status=status.HTTP_403_FORBIDDEN)

        if pk:
            instance = get_object_or_404(AssignRoleToUser, pk=pk)

            serializer = AssignRoleToUserSerializer(instance)
            return Response({"success": True, "data": serializer.data}, status=status.HTTP_200_OK)
        else:
            instances = AssignRoleToUser.objects.all()

            paginator = SizePagination()
            paginated_queryset = paginator.paginate_queryset(instances, request)
            serializer = AssignRoleToUserSerializer(paginated_queryset, many=True)
            paginated_response = paginator.get_paginated_response(serializer.data)

            return Response({"success": True, "data": paginated_response.data}, status=status.HTTP_200_OK)
    
    def delete(self, request, pk):
        """
        Handle DELETE requests for deleting an instance.
        """
        instance = get_object_or_404(AssignRoleToUser, pk=pk)
        
        # Check permission
        if not (request.user.is_superuser or request.user.is_admin):
            return Response({"success": False, "error": "Only admin or super admin can perform this action."}, status=status.HTTP_403_FORBIDDEN)

        instance.delete()

        return Response({"success": True, "message": "Instance deleted successfully."}, status=status.HTTP_200_OK)

# API View for AssignPermissionToRole
class AssignPermissionToRoleAPIView(APIView):
    """
    API endpoint to assign a specific permission to a role.
    Accepts POST requests with data corresponding to the AssignPermissionToRole model.
    """

    permission_classes = [IsAuthenticated, IsOwnerOrAdmin]
    
    def post(self, request):
        serializer = AssignPermissionToRoleSerializer(data=request.data)

        # Check permission
        if not (request.user.is_superuser or request.user.is_admin):
            return Response({"success": False, "error": "Only admin or super admin can perform this action."}, status=status.HTTP_403_FORBIDDEN)

        
        if serializer.is_valid():
            serializer.save(assigned_by=request.user)
            return Response({"success": True, "data": serializer.data}, status=status.HTTP_201_CREATED)
        return Response({"success": False, "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
    
    def get(self, request, pk=None):
        """
        Handle GET requests.
        If `pk` is provided, fetch a single instance; otherwise, fetch all instances.
        """
        # Check permission
        if not (request.user.is_superuser or request.user.is_admin):
            return Response({"success": False, "error": "Only admin or super admin can perform this action."}, status=status.HTTP_403_FORBIDDEN)

        if pk:
            instance = get_object_or_404(AssignPermissionToRole, pk=pk)

            serializer = AssignPermissionToRoleSerializer(instance)
            return Response({"success": True, "data": serializer.data}, status=status.HTTP_200_OK)
        else:
            instances = AssignPermissionToRole.objects.all()

            paginator = SizePagination()
            paginated_queryset = paginator.paginate_queryset(instances, request)
            serializer = AssignPermissionToRoleSerializer(paginated_queryset, many=True)
            paginated_response = paginator.get_paginated_response(serializer.data)

            return Response({"success": True, "data": paginated_response.data}, status=status.HTTP_200_OK)
    
    def delete(self, request, pk):
        """
        Handle DELETE requests for deleting an instance.
        """
        instance = get_object_or_404(AssignPermissionToRole, pk=pk)

        # Check permission
        if not (request.user.is_superuser or request.user.is_admin):
            return Response({"success": False, "error": "Only admin or super admin can perform this action."}, status=status.HTTP_403_FORBIDDEN)

        instance.delete()

        return Response({"success": True, "message": "Instance deleted successfully."}, status=status.HTTP_200_OK)
    
# API View for AssignPermissionsToRole
class AssignPermissionsToRoleAPIView(APIView):
    """
    API endpoint to assign mutiple permissions to a role.
    Accepts POST requests with data corresponding to the AssignPermissionToRole model.
    """

    permission_classes = [IsAuthenticated, IsOwnerOrAdmin]
    
    def post(self, request):
        serializer = AssignPermissionsToRoleSerializer(data=request.data)

        # Check permission
        if not (request.user.is_superuser or request.user.is_admin):
            return Response({"success": False, "error": "Only admin or super admin can perform this action."}, status=status.HTTP_403_FORBIDDEN)

        
        if serializer.is_valid():
            serializer.save(assigned_by=request.user)
            return Response({"success": True, "data": serializer.data}, status=status.HTTP_201_CREATED)
        return Response({"success": False, "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
    
# API View for AssignPermissionToApplication
class AssignPermissionToApplicationAPIView(APIView):
    """
    API endpoint to assign a specific permission to an application.
    Accepts POST requests with data corresponding to the AssignPermissionToApplication model.
    """
    
    permission_classes = [IsAuthenticated, IsOwnerOrAdmin]
    
    def post(self, request):
        serializer = AssignPermissionToApplicationSerializer(data=request.data)

        # Check permission
        if not (request.user.is_superuser or request.user.is_admin):
            return Response({"success": False, "error": "Only admin or super admin can perform this action."}, status=status.HTTP_403_FORBIDDEN)

        if serializer.is_valid():
            serializer.save(assigned_by=request.user)
            return Response({"success": True, "data": serializer.data}, status=status.HTTP_201_CREATED)
        return Response({"success": False, "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request, pk=None):
        """
        Handle GET requests.
        If `pk` is provided, fetch a single instance; otherwise, fetch all instances.
        """
        # Check permission
        if not (request.user.is_superuser or request.user.is_admin):
            return Response({"success": False, "error": "Only admin or super admin can perform this action."}, status=status.HTTP_403_FORBIDDEN)

        if pk:
            instance = get_object_or_404(AssignPermissionApplication, pk=pk)
            
            serializer = AssignPermissionToApplicationSerializer(instance)
            return Response({"success": True, "data": serializer.data}, status=status.HTTP_200_OK)
        else:
            instances = AssignPermissionApplication.objects.all()

            paginator = SizePagination()
            paginated_queryset = paginator.paginate_queryset(instances, request)
            serializer = AssignPermissionToApplicationSerializer(paginated_queryset, many=True)
            paginated_response = paginator.get_paginated_response(serializer.data)

            return Response({"success": True, "data": paginated_response.data}, status=status.HTTP_200_OK)
    
    def delete(self, request, pk):
        """
        Handle DELETE requests for deleting an instance.
        """
        instance = get_object_or_404(AssignPermissionApplication, pk=pk)

        # Check permission
        if not (request.user.is_superuser or request.user.is_admin):
            return Response({"success": False, "error": "Only admin or super admin can perform this action."}, status=status.HTTP_403_FORBIDDEN)

        instance.delete()

        return Response({"success": True, "message": "Instance deleted successfully."}, status=status.HTTP_200_OK)
    

