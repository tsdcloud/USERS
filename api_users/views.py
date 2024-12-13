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


class SizePagination(PageNumberPagination):
    page_size = 100

class UserView(APIView):
    """
    API view to handle CRUD operations for user.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request, pk=None):
        """
        Handle GET requests.
        If `pk` is provided, fetch a single instance; otherwise, fetch all instances.
        """
        if pk:
            instance = get_object_or_404(CustomUser.objects.filter(is_active=True), pk=pk)
            serializer = UserDetailSerializer(instance)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            instances = CustomUser.objects.filter(is_active=True)
            paginator = SizePagination()
            paginated_queryset = paginator.paginate_queryset(instances, request)
            serializer = UserSerializer(paginated_queryset, many=True)
            return paginator.get_paginated_response(serializer.data)
        
    
    def patch(self, request, pk):
        """
        Handle PATCH requests for partially updating an instance.
        """
        instance = get_object_or_404(CustomUser, pk=pk)
        serializer = UserSerializer(instance, data=request.data, partial=True)
        if serializer.is_valid():
            # Check if the user is anonymous
            if isinstance(request.user, AnonymousUser):
                return Response({"error": "Anonymous users cannot perform partial update of this permission instance."}, status=status.HTTP_403_FORBIDDEN)
            
            serializer.save(updated_by=request.user)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
    def post(self, request):
        data = request.data
        first_name = data.get("first_name")
        username = data.get("username")
        last_name = data.get("last_name")
        email = data.get("email")

        random_password = generate_random_chain(12)
        hashed_password = make_password(random_password)

        if not last_name : last_name = ""

        if not first_name or not email:
            return Response({"error": "First name and email are required."}, status=status.HTTP_400_BAD_REQUEST)

        if CustomUser.objects.filter(email=email).exists():
            return Response({"error": "Email is already in use."}, status=status.HTTP_400_BAD_REQUEST)

        # Create a user with a reset token
        reset_token = str(uuid.uuid4())
        token_expiry = now() + timedelta(hours=24)

        if isinstance(request.user, AnonymousUser):
                return Response({"error": "Anonymous users cannot create permissions."}, status=status.HTTP_403_FORBIDDEN)
        
        user = CustomUser.objects.create(
            first_name=first_name,
            email=email,
            reset_token=reset_token,
            reset_token_expire=token_expiry,
            username=username,
            last_name = last_name,
            is_active=False,
            password=hashed_password,
            created_by=request.user,
        )

        # Construct the reset URL
        reset_url = f"{'http://127.0.0.1:8000/api_gateway/api_users/set_password/'}?token={reset_token}"

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

        if not delete :
            if serializer.is_valid():
                serializer.save(is_active=False)
        else:
            instance.delete()

        return Response({"message": "Instance deleted successfully."}, status=status.HTTP_200_OK)


class SetPasswordAPIView(APIView):
    """
    API View to handle password setting using a reset token.
    """

    def post(self, request):
        data = request.data
        token = request.query_params.get('token')
        password = data.get("password")

        if not token or not password:
            return Response({"error": "Token and password are required."}, status=status.HTTP_400_BAD_REQUEST)

        user = CustomUser.objects.filter(reset_token=token).first()

        if not user or user.reset_token_expire < now():
            return Response({"error": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)

        # Set the password and activate the user
        validate_password(password)
        user.password = make_password(password)
        user.reset_token = None
        user.reset_token_expire = None
        user.is_active = True
        user.save()

        return Response({"message": "Password set successfully. You can now log in."}, status=status.HTTP_200_OK)
    
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

    permission_classes = [IsAuthenticated]

    def get(self, request, pk=None):
        """
        Handle GET requests.
        If `pk` is provided, fetch a single instance; otherwise, fetch all instances.
        """
        if pk:
            instance = get_object_or_404(Permission.objects.filter(is_active=True), pk=pk)
            serializer = PermissionSerializer(instance)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            instances = Permission.objects.filter(is_active=True)
            paginator = SizePagination()
            paginated_queryset = paginator.paginate_queryset(instances, request)
            serializer = PermissionSerializer(paginated_queryset, many=True)
            return paginator.get_paginated_response(serializer.data)
        
    def post(self, request):
        """
        Handle POST requests for creating a new instance.
        """
        serializer = PermissionSerializer(data=request.data)
        if serializer.is_valid():
            # Check if the user is anonymous
            if isinstance(request.user, AnonymousUser):
                return Response({"error": "Anonymous users cannot create permissions."}, status=status.HTTP_403_FORBIDDEN)
            
            serializer.save(created_by=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        # Save with the authenticated user as the creator
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, pk):
        """
        Handle PUT requests for updating an instance.
        """
        instance = get_object_or_404(Permission, pk=pk)
        serializer = PermissionSerializer(instance, data=request.data, partial=False)
        if serializer.is_valid():
            # Check if the user is anonymous
            if isinstance(request.user, AnonymousUser):
                return Response({"error": "Anonymous users cannot update permissions."}, status=status.HTTP_403_FORBIDDEN)
            
            serializer.save(updated_by=request.user)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, pk):
        """
        Handle PATCH requests for partially updating an instance.
        """
        instance = get_object_or_404(Permission, pk=pk)
        serializer = PermissionSerializer(instance, data=request.data, partial=True)
        if serializer.is_valid():
            # Check if the user is anonymous
            if isinstance(request.user, AnonymousUser):
                return Response({"error": "Anonymous users cannot perform partial update of this permission instance."}, status=status.HTTP_403_FORBIDDEN)
            
            serializer.save(updated_by=request.user)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        """
        Handle DELETE requests for deleting an instance.
        """
        instance = get_object_or_404(Permission, pk=pk)
        serializer = PermissionSerializer(instance, data=request.data, partial=True)
        # instance.delete()
        if serializer.is_valid():
            serializer.save(is_active=False)
        return Response({"message": "Instance deleted successfully."}, status=status.HTTP_200_OK)

class RoleAPIView(APIView):
    """
    API view to handle CRUD operations for Role.
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request, pk=None):
        """
        Handle GET requests.
        If `pk` is provided, fetch a single instance; otherwise, fetch all instances.
        """
        if pk:
            instance = get_object_or_404(Role.objects.filter(is_active=True), pk=pk)
            serializer = RoleSerializer(instance)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            instances = Role.objects.filter(is_active=True)
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
        if serializer.is_valid():
            # Check if the user is anonymous
            if isinstance(request.user, AnonymousUser):
                return Response({"error": "Anonymous users cannot create role."}, status=status.HTTP_403_FORBIDDEN)
            
            serializer.save(created_by=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        # Save with the authenticated user as the creator
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, pk):
        """
        Handle PUT requests for updating an instance.
        """
        instance = get_object_or_404(Role, pk=pk)
        serializer = RoleSerializer(instance, data=request.data, partial=False)
        if serializer.is_valid():
            # Check if the user is anonymous
            if isinstance(request.user, AnonymousUser):
                return Response({"error": "Anonymous users cannot create role."}, status=status.HTTP_403_FORBIDDEN)
            
            serializer.save(updated_by=request.user)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, pk):
        """
        Handle PATCH requests for partially updating an instance.
        """
        instance = get_object_or_404(Role, pk=pk)
        serializer = RoleSerializer(instance, data=request.data, partial=True)
        if serializer.is_valid():
            # Check if the user is anonymous
            if isinstance(request.user, AnonymousUser):
                return Response({"error": "Anonymous users cannot create role."}, status=status.HTTP_403_FORBIDDEN)
            
            serializer.save(updated_by=request.user)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        """
        Handle DELETE requests for deleting an instance.
        """
        instance = get_object_or_404(Role, pk=pk)
        serializer = RoleSerializer(instance, data=request.data, partial=True)
        # instance.delete()
        if serializer.is_valid():
            serializer.save(is_active=False)
        return Response({"message": "Instance deleted successfully."}, status=status.HTTP_204_NO_CONTENT)

class ApplicationAPIView(APIView):
    """
    API view to handle CRUD operations for Application.
    """

    permission_classes = [IsAuthenticated]
    
    def get(self, request, pk=None):
        """
        Handle GET requests.
        If `pk` is provided, fetch a single instance; otherwise, fetch all instances.
        """
        if pk:
            instance = get_object_or_404(Application.objects.filter(is_active=True), pk=pk)
            serializer = ApplicationSerializer(instance)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            instances = Application.objects.filter(is_active=True)
            paginator = SizePagination()
            paginated_queryset = paginator.paginate_queryset(instances, request)
            serializer = ApplicationSerializer(paginated_queryset, many=True)
            return paginator.get_paginated_response(serializer.data)
        
    def post(self, request):
        """
        Handle POST requests for creating a new instance.
        """
        serializer = ApplicationSerializer(data=request.data)
        if serializer.is_valid():
            # Check if the user is anonymous
            if isinstance(request.user, AnonymousUser):
                return Response({"error": "Anonymous users cannot create application."}, status=status.HTTP_403_FORBIDDEN)
            
            serializer.save(created_by=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        # Save with the authenticated user as the creator
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, pk):
        """
        Handle PUT requests for updating an instance.
        """
        instance = get_object_or_404(Application, pk=pk)
        serializer = ApplicationSerializer(instance, data=request.data, partial=False)
        if serializer.is_valid():
            # Check if the user is anonymous
            if isinstance(request.user, AnonymousUser):
                return Response({"error": "Anonymous users cannot create application."}, status=status.HTTP_403_FORBIDDEN)
            
            serializer.save(updated_by=request.user)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, pk):
        """
        Handle PATCH requests for partially updating an instance.
        """
        instance = get_object_or_404(Application, pk=pk)
        serializer = ApplicationSerializer(instance, data=request.data, partial=True)
        if serializer.is_valid():
            # Check if the user is anonymous
            if isinstance(request.user, AnonymousUser):
                return Response({"error": "Anonymous users cannot create application."}, status=status.HTTP_403_FORBIDDEN)
            
            serializer.save(updated_by=request.user)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        """
        Handle DELETE requests for deleting an instance.
        """
        instance = get_object_or_404(Application, pk=pk)
        serializer = ApplicationSerializer(instance, data=request.data, partial=True)
        # instance.delete()
        if serializer.is_valid():
            serializer.save(is_active=False)
        return Response({"message": "Instance deleted successfully."}, status=status.HTTP_204_NO_CONTENT)

# API View for AssignPermissionToUser
class AssignPermissionToUserAPIView(APIView):
    """
    API endpoint to assign a specific permission to a user.
    Accepts POST and GET requests with data corresponding to the AssignPermissionToUser model.
    """
    
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        serializer = AssignPermissionToUserSerializer(data=request.data)
        if serializer.is_valid():
            # Check if the user is anonymous
            if isinstance(request.user, AnonymousUser):
                return Response({"error": "Anonymous users cannot create application."}, status=status.HTTP_403_FORBIDDEN)
            
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
            serializer = AssignPermissionToUserSerializer(instance)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            instances = AssignPermissionToUser.objects.all()
            paginator = SizePagination()
            paginated_queryset = paginator.paginate_queryset(instances, request)
            serializer = AssignPermissionToUserSerializer(paginated_queryset, many=True)
            return paginator.get_paginated_response(serializer.data)
    
    def delete(self, request, pk):
        """
        Handle DELETE requests for deleting an instance.
        """
        instance = get_object_or_404(AssignPermissionToUser, pk=pk)

        instance.delete()

        return Response({"message": "Instance deleted successfully."}, status=status.HTTP_200_OK)

# API View for AssignRoleToUser
class AssignRoleToUserAPIView(APIView):
    """
    API endpoint to assign a specific role to a user.
    Accepts POST requests with data corresponding to the AssignRoleToUser model.
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        serializer = AssignRoleToUserSerializer(data=request.data)
        if serializer.is_valid():
            # Check if the user is anonymous
            if isinstance(request.user, AnonymousUser):
                return Response({"error": "Anonymous users cannot create application."}, status=status.HTTP_403_FORBIDDEN)
            
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
            serializer = AssignRoleToUserSerializer(instance)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            instances = AssignRoleToUser.objects.all()
            paginator = SizePagination()
            paginated_queryset = paginator.paginate_queryset(instances, request)
            serializer = AssignRoleToUserSerializer(paginated_queryset, many=True)
            return paginator.get_paginated_response(serializer.data)
    
    def delete(self, request, pk):
        """
        Handle DELETE requests for deleting an instance.
        """
        instance = get_object_or_404(AssignRoleToUser, pk=pk)

        instance.delete()

        return Response({"message": "Instance deleted successfully."}, status=status.HTTP_200_OK)

# API View for AssignPermissionToRole
class AssignPermissionToRoleAPIView(APIView):
    """
    API endpoint to assign a specific permission to a role.
    Accepts POST requests with data corresponding to the AssignPermissionToRole model.
    """

    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        serializer = AssignPermissionToRoleSerializer(data=request.data)
        if serializer.is_valid():
            # Check if the user is anonymous
            if isinstance(request.user, AnonymousUser):
                return Response({"error": "Anonymous users cannot create application."}, status=status.HTTP_403_FORBIDDEN)
            
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
            serializer = AssignPermissionToRoleSerializer(instance)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            instances = AssignPermissionToRole.objects.all()
            paginator = SizePagination()
            paginated_queryset = paginator.paginate_queryset(instances, request)
            serializer = AssignPermissionToRoleSerializer(paginated_queryset, many=True)
            return paginator.get_paginated_response(serializer.data)
    
    def delete(self, request, pk):
        """
        Handle DELETE requests for deleting an instance.
        """
        instance = get_object_or_404(AssignPermissionToRole, pk=pk)

        instance.delete()

        return Response({"message": "Instance deleted successfully."}, status=status.HTTP_200_OK)
    
# API View for AssignPermissionToApplication
class AssignPermissionToApplicationAPIView(APIView):
    """
    API endpoint to assign a specific permission to an application.
    Accepts POST requests with data corresponding to the AssignPermissionToApplication model.
    """
    
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        serializer = AssignPermissionToApplicationSerializer(data=request.data)
        if serializer.is_valid():
            # Check if the user is anonymous
            if isinstance(request.user, AnonymousUser):
                return Response({"error": "Anonymous users cannot create application."}, status=status.HTTP_403_FORBIDDEN)
            
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
            serializer = AssignPermissionToApplicationSerializer(instance)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            instances = AssignPermissionApplication.objects.all()
            paginator = SizePagination()
            paginated_queryset = paginator.paginate_queryset(instances, request)
            serializer = AssignPermissionToApplicationSerializer(paginated_queryset, many=True)
            return paginator.get_paginated_response(serializer.data)
    
    def delete(self, request, pk):
        """
        Handle DELETE requests for deleting an instance.
        """
        instance = get_object_or_404(AssignPermissionApplication, pk=pk)

        instance.delete()

        return Response({"message": "Instance deleted successfully."}, status=status.HTTP_200_OK)

