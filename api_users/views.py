from .models import CustomUser, Permission, Role, Application, AssignPermissionToUser, AssignRoleToUser, AssignPermissionToRole, AssignPermissionApplication
from .serializers import UserSerializer, PermissionSerializer, ApplicationSerializer, RoleSerializer, AssignPermissionToUserSerializer, AssignRoleToUserSerializer, AssignPermissionToRoleSerializer, AssignPermissionToApplicationSerializer, PermissionToUserListSerializer
from rest_framework.viewsets import ModelViewSet
from rest_framework.views import APIView
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.response import Response
from django.contrib.auth.models import AnonymousUser
from rest_framework.pagination import PageNumberPagination


class SizePagination(PageNumberPagination):
    page_size = 100

class UserView(ModelViewSet):
    """
    ModelviewSet to user.
    """
    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer

class PermissionAPIView(APIView):
    """
    API view to handle CRUD operations for Permission.
    """

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
                return Response({"error": "Anonymous users cannot create permissions."}, status=status.HTTP_403_FORBIDDEN)
            
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
                return Response({"error": "Anonymous users cannot create permissions."}, status=status.HTTP_403_FORBIDDEN)
            
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
        return Response({"message": "Instance deleted successfully."}, status=status.HTTP_204_NO_CONTENT)

class RoleAPIView(APIView):
    """
    API view to handle CRUD operations for Role.
    """

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
            instance = get_object_or_404(AssignPermissionToUser.objects.all())
            serializer = PermissionToUserListSerializer(instance)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            instances = AssignPermissionToUser.objects.all()
            paginator = SizePagination()
            paginated_queryset = paginator.paginate_queryset(instances, request)
            serializer = PermissionToUserListSerializer(paginated_queryset, many=True)
            return paginator.get_paginated_response(serializer.data)

# API View for AssignRoleToUser
class AssignRoleToUserAPIView(APIView):
    """
    API endpoint to assign a specific role to a user.
    Accepts POST requests with data corresponding to the AssignRoleToUser model.
    """
    def post(self, request):
        serializer = AssignRoleToUserSerializer(data=request.data)
        if serializer.is_valid():
            # Check if the user is anonymous
            if isinstance(request.user, AnonymousUser):
                return Response({"error": "Anonymous users cannot create application."}, status=status.HTTP_403_FORBIDDEN)
            
            serializer.save(assigned_by=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# API View for AssignPermissionToRole
class AssignPermissionToRoleAPIView(APIView):
    """
    API endpoint to assign a specific permission to a role.
    Accepts POST requests with data corresponding to the AssignPermissionToRole model.
    """
    def post(self, request):
        serializer = AssignPermissionToRoleSerializer(data=request.data)
        if serializer.is_valid():
            # Check if the user is anonymous
            if isinstance(request.user, AnonymousUser):
                return Response({"error": "Anonymous users cannot create application."}, status=status.HTTP_403_FORBIDDEN)
            
            serializer.save(assigned_by=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
# API View for AssignPermissionToApplication
class AssignPermissionToApplicationAPIView(APIView):
    """
    API endpoint to assign a specific permission to an application.
    Accepts POST requests with data corresponding to the AssignPermissionToApplication model.
    """
    def post(self, request):
        serializer = AssignPermissionToApplicationSerializer(data=request.data)
        if serializer.is_valid():
            # Check if the user is anonymous
            if isinstance(request.user, AnonymousUser):
                return Response({"error": "Anonymous users cannot create application."}, status=status.HTTP_403_FORBIDDEN)
            
            serializer.save(assigned_by=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

