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
    UserDetailSerializer )

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


class SizePagination(PageNumberPagination):
    page_size = 100  # default page size
    page_size_query_param = 'page_size'
    max_page_size = 1000


class IsOwnerOrAdmin(permissions.BasePermission):
    """
    Personalized permissions that allow access only if the user
    is acting on his or her own data, or if he or she is an administrator or super-administrator.
    """

    def has_object_permission(self, request, view, obj):
        # Check if the user is an administrator or super administrator or admin
        if request.user.is_superuser or request.user.is_staff or request.user.is_admin:
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
            if request.user.is_superuser == True or request.user.is_admin == True:
                instance = get_object_or_404(CustomUser, pk=pk)

            # Check permission
            self.check_object_permissions(request, instance)

            serializer = UserDetailSerializer(instance)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            # instances = CustomUser.objects.filter(is_active=True)
            if request.user.is_superuser == True:
                instances = CustomUser.objects.all()
            elif request.user.is_admin == True:
                instances = CustomUser.objects.filter(is_active=True)
                
            # Check permission
            self.check_object_permissions(request, instances)

            paginator = SizePagination()
            paginated_queryset = paginator.paginate_queryset(instances, request)
            serializer = UserSerializer(paginated_queryset, many=True)
            return paginator.get_paginated_response(serializer.data)
        
    
    def patch(self, request, pk):
        """
        Handle PATCH requests for partially updating an instance.
        """
        instance = get_object_or_404(CustomUser, pk=pk)

        # Check permission
        self.check_object_permissions(request, instance)
        
        serializer = UserSerializer(instance, data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save(updated_by=request.user)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

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
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

    def post(self, request):
        data = request.data
        first_name = data.get("first_name")
        username = data.get("username")
        last_name = data.get("last_name")
        email = data.get("email")
        phone = data.get("phone")

        random_password = generate_random_chain(12)
        hashed_password = make_password(random_password)

        # Check permission
        if not request.user.is_superuser or not request.user.is_staff:
            return Response({"error": "Only admin or super admin can create users."}, status=status.HTTP_403_FORBIDDEN)

        if not last_name : last_name = ""

        if not phone : phone = ""

        if not first_name or not email:
            return Response({"error": "First name and email are required."}, status=status.HTTP_400_BAD_REQUEST)

        if CustomUser.objects.filter(email=email).exists():
            return Response({"error": "Email is already in use."}, status=status.HTTP_400_BAD_REQUEST)

        # Create a user with a reset token
        reset_token = str(uuid.uuid4())
        token_expiry = now() + timedelta(hours=24)

        user = CustomUser.objects.create(
            first_name=first_name,
            email=email,
            reset_token=reset_token,
            reset_token_expire=token_expiry,
            username=username,
            last_name = last_name,
            is_active=False,
            phone=phone,
            password=hashed_password,
            created_by=request.user,
        )

        # Construct the reset URL
        reset_url = f"{'http://localhost:5173/confirmPassword/'}?token={reset_token}"

        # Send email with the reset link
        send_mail(
            "Set Your Password",
            f"Hi {first_name},\nPlease click the link below to set your password:\n{reset_url}",
            "tsd@bfclimited.com",
            [email],
            fail_silently=False,
            html_message=f"""
                <p>Hi {first_name},</p>
                <p>Please click the link below to set your password:</p>
                <a href="{reset_url}">Set Your Password</a>
            """
        )

        serialiser = UserSerializer(user)
        return Response({"success": serialiser.data}, status=status.HTTP_201_CREATED)
    
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
        elif request.user.is_staff or request.user.is_superuser:
            instance.delete()
        else:
            return Response({"error": "Only admin can perform this action."}, status=status.HTTP_403_FORBIDDEN)

        return Response({"message": "Instance deleted successfully."}, status=status.HTTP_200_OK)


class SetPasswordAPIView(APIView):
    """
    API View to handle password setting using a reset token.
    """

    def post(self, request):
        data = request.data
        token = request.query_params.get('token')
        password = data.get("password")
        confirm_password = data.get("confirm_password")

        if not token or not password or not confirm_password :
            return Response({"error": "Token, password and confirm_password are required."}, status=status.HTTP_400_BAD_REQUEST)
        
        if password != confirm_password :
            return Response({"error": "the provided passwords are not equal !!"}, status=status.HTTP_400_BAD_REQUEST)

        user = CustomUser.objects.filter(reset_token=token).first()

        if not user or user.reset_token_expire < now():
            return Response({"error": "expired token."}, status=status.HTTP_400_BAD_REQUEST)

        # Set the password and activate the user
        validate_password(password)
        user.password = make_password(password)
        user.reset_token = None
        user.reset_token_expire = None
        user.is_active = True
        user.save()

        return Response({"message": "Password set successfully. You can now log in."}, status=status.HTTP_200_OK)

class EmailToResetPasswordAPIView(APIView):
    """
    API View to get email to reset password.
    """

    # permission_classes = [IsOwnerOrAdmin, IsAuthenticated]

    def post(self, request):
        data = request.data
        email = data.get("email")

        # print(request.user.email)

        # Create a token to use to reset the password
        reset_token = str(uuid.uuid4())
        token_expiry = now() + timedelta(hours=24)

        user = CustomUser.objects.filter(email=email).first()

        # Check permission
        self.check_object_permissions(request, user)

        # Construct the reset URL 
        reset_url = f"{'http://localhost:5173/confirmPassword/'}?token={reset_token}"
        # reset_url = f"{'http://127.0.0.1:8000/api_gateway/api/reset_password/'}?token={reset_token}"

        # Send email with the reset link
        send_mail(
            "Set Your Password",
            f"Hi {user.first_name},\nPlease click the link below to reset your password:\n{reset_url}",
            "tsd@bfclimited.com",
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

        return Response({"success": "email sent succesfully, check your email and follow the instruction."}, status=status.HTTP_200_OK)

class ChangePasswordAPIView(APIView):
    """
    API View to change setting without using a token.
    """

    permission_classes = [IsOwnerOrAdmin, IsAuthenticated]

    def post(self, request):
        data = request.data
        password = data.get("password")
        confirm_password = data.get("confirm_password")

        email = request.user.email

        if not password or not confirm_password :
            return Response({"error": "Password and confirm_password are required."}, status=status.HTTP_400_BAD_REQUEST)
        
        if password != confirm_password :
            return Response({"error": "the provided passwords are not equal !!"}, status=status.HTTP_400_BAD_REQUEST)

        user = CustomUser.objects.filter(email=email).first()

        # Set the password and activate the user
        validate_password(password)
        user.password = make_password(password)
        user.save()

        return Response({"message": "Password change successfully."}, status=status.HTTP_200_OK)

# class EmailToChangePasswordAPIView(APIView):
#     """
#     API View to get email to change password.
#     """

#     permission_classes = [IsOwnerOrAdmin, IsAuthenticated]

#     def post(self, request):

#         email = request.user.email

#         # print(request.user.email)

#         # Create a token to use to reset the password
#         reset_token = str(uuid.uuid4())
#         token_expiry = now() + timedelta(hours=24)

#         user = CustomUser.objects.filter(email=email).first()

#         # Check permission
#         self.check_object_permissions(request, user)

#         # Construct the reset URL 
#         reset_url = f"{'http://localhost:5173/confirmPassword/'}?token={reset_token}"
#         # reset_url = f"{'http://127.0.0.1:8000/api_gateway/api/reset_password/'}?token={reset_token}"

#         # Send email with the reset link
#         send_mail(
#             "Set Your Password",
#             f"Hi {user.first_name},\nPlease click the link below to reset your password:\n{reset_url}",
#             "tsd@bfclimited.com",
#             [email],
#             fail_silently=False,
#             html_message=f"""
#                 <p>Hi {user.first_name},</p>
#                 <p>Please click the link below to reset your password:</p>
#                 <a href="{reset_url}">Set Your Password</a>
#             """
#         )

#         user.reset_token = reset_token
#         user.reset_token_expire = token_expiry
#         user.save()

#         return Response({"success": "email sent succesfully, check your email and follow the instruction."}, status=status.HTTP_200_OK)

# class ResetPasswordAPIView(APIView):
#     """
#     API View to reset password.
#     """
#     permission_classes = [IsOwnerOrAdmin, IsAuthenticated]

#     def post(self, request):
#         data = request.data
#         token = request.query_params.get('token')
#         password = data.get("password")
#         confirm_password = data.get("confirm_password")

#         if not token:
#             return Response({"error": "Token are required."}, status=status.HTTP_400_BAD_REQUEST)
        
#         if password != confirm_password :
#             return Response({"error": "the provided passwords are not equal !!"}, status=status.HTTP_400_BAD_REQUEST)

#         user = CustomUser.objects.filter(reset_token=token).first()

#         # Check permission
#         self.check_object_permissions(request, user)

#         if not user or user.reset_token_expire < now():
#             return Response({"error": "expired token."}, status=status.HTTP_400_BAD_REQUEST)

#         # Set the password and activate the user
#         validate_password(password)
#         user.password = make_password(password)
#         user.reset_token = None
#         user.reset_token_expire = None
#         user.save()

#         return Response({"message": "Password reset successfully. You can now log in."}, status=status.HTTP_200_OK)

class SearchUserView(APIView):
    """
    View to search for users based on query parameters.
    """

    permission_classes = [IsAuthenticated]
    
    def get(self, request):
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
            filters &= Q(username__icontains=is_active)

        paginator = SizePagination()
        users = CustomUser.objects.filter(filters)
        paginated_queryset = paginator.paginate_queryset(users, request)
        serializer = UserSerializer(paginated_queryset, many=True)

        # Return list of users found
        return paginator.get_paginated_response(serializer.data)
    

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
            self.check_object_permissions(request, instance)

            serializer = PermissionSerializer(instance)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            instances = Permission.objects.filter(is_active=True)
            
            # Check permission
            self.check_object_permissions(request, instances)

            paginator = SizePagination()
            paginated_queryset = paginator.paginate_queryset(instances, request)
            serializer = PermissionSerializer(paginated_queryset, many=True)
            return paginator.get_paginated_response(serializer.data)
        
    def post(self, request):
        """
        Handle POST requests for creating a new instance.
        """
        serializer = PermissionSerializer(data=request.data)

        # Check permission
        if not request.user.is_superuser or not request.user.is_staff:
            return Response({"error": "Only admin or super admin can create users."}, status=status.HTTP_403_FORBIDDEN)
        
        if serializer.is_valid():
            serializer.save(created_by=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        # Save with the authenticated user as the creator
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, pk):
        """
        Handle PUT requests for updating an instance.
        """
        instance = get_object_or_404(Permission, pk=pk)

        # Check permission
        self.check_object_permissions(request, instance)

        serializer = PermissionSerializer(instance, data=request.data, partial=False)
        if serializer.is_valid():
            serializer.save(updated_by=request.user)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, pk):
        """
        Handle PATCH requests for partially updating an instance.
        """
        instance = get_object_or_404(Permission, pk=pk)

        # Check permission
        self.check_object_permissions(request, instance)

        serializer = PermissionSerializer(instance, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save(updated_by=request.user)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        """
        Handle DELETE requests for deleting an instance.
        """
        instance = get_object_or_404(Permission, pk=pk)
        # Check permission
        self.check_object_permissions(request, instance)
        serializer = PermissionSerializer(instance, data=request.data, partial=True)
        # instance.delete()
        if serializer.is_valid():
            serializer.save(is_active=False)
        return Response({"message": "Instance deleted successfully."}, status=status.HTTP_200_OK)

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
            self.check_object_permissions(request, instance)

            serializer = RoleSerializer(instance)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            instances = Role.objects.filter(is_active=True)
            
            # Check permission
            self.check_object_permissions(request, instances)

            paginator = SizePagination()
            paginated_queryset = paginator.paginate_queryset(instances, request)
            serializer = RoleSerializer(paginated_queryset, many=True)
            return paginator.get_paginated_response(serializer.data)
        
            # instances = Role.objects.filter(is_active=True)
            # serializer = RoleSerializer(instances, many=True)
            # return Response(serializer.data, status=status.HTTP_200_OK)
        
    def post(self, request):
        """
        Handle POST requests for creating a new instance.
        """
        serializer = RoleSerializer(data=request.data)

        # Check permission
        if not request.user.is_superuser or not request.user.is_staff:
            return Response({"error": "Only admin or super admin can create users."}, status=status.HTTP_403_FORBIDDEN)
        
        if serializer.is_valid():
            serializer.save(created_by=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        # Save with the authenticated user as the creator
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, pk):
        """
        Handle PUT requests for updating an instance.
        """
        instance = get_object_or_404(Role, pk=pk)
        
        # Check permission
        self.check_object_permissions(request, instance)

        serializer = RoleSerializer(instance, data=request.data, partial=False)
        if serializer.is_valid():
            serializer.save(updated_by=request.user)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, pk):
        """
        Handle PATCH requests for partially updating an instance.
        """
        instance = get_object_or_404(Role, pk=pk)

        # Check permission
        self.check_object_permissions(request, instance)
        
        serializer = RoleSerializer(instance, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save(updated_by=request.user)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        """
        Handle DELETE requests for deleting an instance.
        """
        instance = get_object_or_404(Role, pk=pk)

        # Check permission
        self.check_object_permissions(request, instance)

        serializer = RoleSerializer(instance, data=request.data, partial=True)
        # instance.delete()
        if serializer.is_valid():
            serializer.save(is_active=False)
        return Response({"message": "Instance deleted successfully."}, status=status.HTTP_200_OK)

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
        if pk:
            instance = get_object_or_404(Application.objects.filter(is_active=True), pk=pk)
            
            # Check permission
            self.check_object_permissions(request, instance)

            serializer = ApplicationSerializer(instance)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            instances = Application.objects.filter(is_active=True)

            # Check permission
            self.check_object_permissions(request, instances)

            paginator = SizePagination()
            paginated_queryset = paginator.paginate_queryset(instances, request)
            serializer = ApplicationSerializer(paginated_queryset, many=True)
            return paginator.get_paginated_response(serializer.data)
        
    def post(self, request):
        """
        Handle POST requests for creating a new instance.
        """
        serializer = ApplicationSerializer(data=request.data)

        # Check permission
        if not request.user.is_superuser or not request.user.is_staff:
            return Response({"error": "Only admin or super admin can create users."}, status=status.HTTP_403_FORBIDDEN)
        
        if serializer.is_valid():
            serializer.save(created_by=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        # Save with the authenticated user as the creator
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, pk):
        """
        Handle PUT requests for updating an instance.
        """
        instance = get_object_or_404(Application, pk=pk)
        
        # Check permission
        self.check_object_permissions(request, instance)

        serializer = ApplicationSerializer(instance, data=request.data, partial=False)
        if serializer.is_valid():
            serializer.save(updated_by=request.user)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, pk):
        """
        Handle PATCH requests for partially updating an instance.
        """
        instance = get_object_or_404(Application, pk=pk)

        # Check permission
        self.check_object_permissions(request, instance)
        
        serializer = ApplicationSerializer(instance, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save(updated_by=request.user)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        """
        Handle DELETE requests for deleting an instance.
        """
        instance = get_object_or_404(Application, pk=pk)
        
        # Check permission
        self.check_object_permissions(request, instance)
        
        serializer = ApplicationSerializer(instance, data=request.data, partial=True)
        # instance.delete()
        if serializer.is_valid():
            serializer.save(is_active=False)
        return Response({"message": "Instance deleted successfully."}, status=status.HTTP_200_OK)

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
        if not request.user.is_superuser or not request.user.is_staff:
            return Response({"error": "Only admin or super admin can create users."}, status=status.HTTP_403_FORBIDDEN)
        
        if serializer.is_valid():
            serializer.save(assigned_by=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def get(self, request, pk=None):
        """
        Handle GET requests.
        If `pk` is provided, fetch a single instance; otherwise, fetch all instances.
        """
        if pk:
            instance = get_object_or_404(AssignPermissionToUser, pk=pk)
                        
            # Check permission
            self.check_object_permissions(request, instance)

            serializer = AssignPermissionToUserSerializer(instance)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            instances = AssignPermissionToUser.objects.all()
            
            # Check permission
            self.check_object_permissions(request, instances)

            paginator = SizePagination()
            paginated_queryset = paginator.paginate_queryset(instances, request)
            serializer = AssignPermissionToUserSerializer(paginated_queryset, many=True)
            return paginator.get_paginated_response(serializer.data)
    
    def delete(self, request, pk):
        """
        Handle DELETE requests for deleting an instance.
        """
        instance = get_object_or_404(AssignPermissionToUser, pk=pk)

        # Check permission
        self.check_object_permissions(request, instance)

        instance.delete()

        return Response({"message": "Instance deleted successfully."}, status=status.HTTP_200_OK)

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
        if not request.user.is_superuser or not request.user.is_staff:
            return Response({"error": "Only admin or super admin can create users."}, status=status.HTTP_403_FORBIDDEN)
        
        if serializer.is_valid():
            serializer.save(assigned_by=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def get(self, request, pk=None):
        """
        Handle GET requests.
        If `pk` is provided, fetch a single instance; otherwise, fetch all instances.
        """
        
        if pk:
            instance = get_object_or_404(AssignRoleToUser, pk=pk)

            # Check permission
            self.check_object_permissions(request, instance)

            serializer = AssignRoleToUserSerializer(instance)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            instances = AssignRoleToUser.objects.all()

            # Check permission
            self.check_object_permissions(request, instances)

            paginator = SizePagination()
            paginated_queryset = paginator.paginate_queryset(instances, request)
            serializer = AssignRoleToUserSerializer(paginated_queryset, many=True)
            return paginator.get_paginated_response(serializer.data)
    
    def delete(self, request, pk):
        """
        Handle DELETE requests for deleting an instance.
        """
        instance = get_object_or_404(AssignRoleToUser, pk=pk)

        # Check permission
        self.check_object_permissions(request, instance)

        instance.delete()

        return Response({"message": "Instance deleted successfully."}, status=status.HTTP_200_OK)

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
        if not request.user.is_superuser or not request.user.is_staff:
            return Response({"error": "Only admin or super admin can create users."}, status=status.HTTP_403_FORBIDDEN)
        
        if serializer.is_valid():
            serializer.save(assigned_by=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def get(self, request, pk=None):
        """
        Handle GET requests.
        If `pk` is provided, fetch a single instance; otherwise, fetch all instances.
        """
        if pk:
            instance = get_object_or_404(AssignPermissionToRole, pk=pk)

            # Check permission
            self.check_object_permissions(request, instance)

            serializer = AssignPermissionToRoleSerializer(instance)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            instances = AssignPermissionToRole.objects.all()

            # Check permission
            self.check_object_permissions(request, instances)


            paginator = SizePagination()
            paginated_queryset = paginator.paginate_queryset(instances, request)
            serializer = AssignPermissionToRoleSerializer(paginated_queryset, many=True)
            return paginator.get_paginated_response(serializer.data)
    
    def delete(self, request, pk):
        """
        Handle DELETE requests for deleting an instance.
        """
        instance = get_object_or_404(AssignPermissionToRole, pk=pk)

        # Check permission
        self.check_object_permissions(request, instance)

        instance.delete()

        return Response({"message": "Instance deleted successfully."}, status=status.HTTP_200_OK)
    
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
        if not request.user.is_superuser or not request.user.is_staff:
            return Response({"error": "Only admin or super admin can create users."}, status=status.HTTP_403_FORBIDDEN)
        
        if serializer.is_valid():
            serializer.save(assigned_by=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request, pk=None):
        """
        Handle GET requests.
        If `pk` is provided, fetch a single instance; otherwise, fetch all instances.
        """
        if pk:
            instance = get_object_or_404(AssignPermissionApplication, pk=pk)

            # Check permission
            self.check_object_permissions(request, instance)
            
            serializer = AssignPermissionToApplicationSerializer(instance)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            instances = AssignPermissionApplication.objects.all()

            # Check permission
            self.check_object_permissions(request, instances)

            paginator = SizePagination()
            paginated_queryset = paginator.paginate_queryset(instances, request)
            serializer = AssignPermissionToApplicationSerializer(paginated_queryset, many=True)
            return paginator.get_paginated_response(serializer.data)
    
    def delete(self, request, pk):
        """
        Handle DELETE requests for deleting an instance.
        """
        instance = get_object_or_404(AssignPermissionApplication, pk=pk)

        # Check permission
        self.check_object_permissions(request, instance)

        instance.delete()

        return Response({"message": "Instance deleted successfully."}, status=status.HTTP_200_OK)

