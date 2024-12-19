from rest_framework import serializers
from .models import (
    CustomUser, 
    Permission, 
    Role, 
    Application, 
    AssignPermissionToUser, 
    AssignRoleToUser, 
    AssignPermissionToRole, 
    AssignPermissionApplication 
)

import re


class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for the User model, used for creating and updating users.
    """

    user_created_by = serializers.SerializerMethodField()
    user_updated_by = serializers.SerializerMethodField()

    class Meta:
        model = CustomUser
        fields = ['id', 'email', 'username', 'first_name', 'last_name', 'phone', 'is_staff', 'is_active', 'is_superuser', 'user_created_by', 'user_updated_by']
        extra_kwargs = {
            'password': {'write_only': True},
        }
    
    def get_user_created_by(self, obj):
        return {
            "id": obj.created_by.id,
            "username": obj.created_by.username,
            "email": obj.created_by.email,
            "first_name": obj.created_by.first_name,
            "last_name": obj.created_by.last_name,
            "phone": obj.created_by.phone
        } if obj.created_by else None
    
    def get_user_updated_by(self, obj):
        return {
            "id": obj.updated_by.id,
            "username": obj.updated_by.username,
            "email": obj.updated_by.email,
            "first_name": obj.updated_by.first_name,
            "last_name": obj.updated_by.last_name,
            "phone": obj.updated_by.phone
        } if obj.updated_by else None
    
    def update(self, instance, validated_data):
        validated_data.pop('password', None)
        return super().update(instance, validated_data)


class PermissionSerializer(serializers.ModelSerializer):
    """
    Serializer to create, update, and retrieve permissions.

    - Allows the creation and updating of permission names, descriptions, and active status.
    """

    perm_created_by = serializers.SerializerMethodField()
    perm_updated_by = serializers.SerializerMethodField()
    
    class Meta:
        model = Permission
        fields = ['id', 'permission_name', 'description', 'perm_created_by', 'perm_updated_by']
        read_only_fields = ['created_by', 'date_created']
    
    def get_perm_created_by(self, obj):
        return {
            "id": obj.created_by.id,
            "username": obj.created_by.username,
            "email": obj.created_by.email,
            "first_name": obj.created_by.first_name,
            "last_name": obj.created_by.last_name,
            "phone": obj.created_by.phone
        } if obj.created_by else None
    
    def get_perm_updated_by(self, obj):
        return {
            "id": obj.updated_by.id,
            "username": obj.updated_by.username,
            "email": obj.updated_by.email,
            "first_name": obj.updated_by.first_name,
            "last_name": obj.updated_by.last_name,
            "phone": obj.updated_by.phone
        } if obj.updated_by else None


class RoleSerializer(serializers.ModelSerializer):
    """
    Serializer to create, update, and retrieve roles.

    - Allows the creation and updating of role names, descriptions, and active status.
    """

    role_created_by = serializers.SerializerMethodField()
    role_updated_by = serializers.SerializerMethodField()

    class Meta:
        model = Role
        fields = ['id', 'role_name', 'description', 'role_created_by', 'role_updated_by']
    
    def get_role_created_by(self, obj):
        return {
            "id": obj.created_by.id,
            "username": obj.created_by.username,
            "email": obj.created_by.email,
            "first_name": obj.created_by.first_name,
            "last_name": obj.created_by.last_name,
            "phone": obj.created_by.phone
        } if obj.created_by else None
    
    def get_role_updated_by(self, obj):
        return {
            "id": obj.updated_by.id,
            "username": obj.updated_by.username,
            "email": obj.updated_by.email,
            "first_name": obj.updated_by.first_name,
            "last_name": obj.updated_by.last_name,
            "phone": obj.updated_by.phone
        } if obj.updated_by else None

class ApplicationSerializer(serializers.ModelSerializer):
    """
    Serializer to create, update, and retrieve applications.

    - Allows the creation and updating of application name, description, URL, and active status.
    """

    app_created_by = serializers.SerializerMethodField()
    app_updated_by = serializers.SerializerMethodField()

    class Meta:
        model = Application
        fields = ['id', 'application_name', 'description', 'url', 'app_created_by', 'app_updated_by']
        read_only_fields = ['created_by', 'date_created']
    
    def get_app_created_by(self, obj):
        return {
            "id": obj.created_by.id,
            "username": obj.created_by.username,
            "email": obj.created_by.email,
            "first_name": obj.created_by.first_name,
            "last_name": obj.created_by.last_name,
            "phone": obj.created_by.phone
        } if obj.created_by else None
    
    def get_app_updated_by(self, obj):
        return {
            "id": obj.updated_by.id,
            "username": obj.updated_by.username,
            "email": obj.updated_by.email,
            "first_name": obj.updated_by.first_name,
            "last_name": obj.updated_by.last_name,
            "phone": obj.updated_by.phone
        } if obj.updated_by else None


# Serializer for AssignPermissionToUser
class AssignPermissionToUserSerializer(serializers.ModelSerializer):
    """
    Serializer for assigning a permission to a user.
    Converts model instances to JSON and validates incoming data for the AssignPermissionToUser model.
    """

    user = serializers.SerializerMethodField()
    permission = serializers.SerializerMethodField()
    perm_assigned_by = serializers.SerializerMethodField()

    class Meta:
        model = AssignPermissionToUser
        fields = ['id', 'user_id', 'permission_id', 'user', 'permission', 'perm_assigned_by', 'date_assigned']
        extra_kwargs = {
            'user_id': {'write_only': True},
            'permission_id': {'write_only': True}
        }
    
    def validate(self, data):
        # Check if a similar assignment already exists
        if AssignPermissionToUser.objects.filter(user_id=data['user_id'], permission_id=data['permission_id']).exists():
            raise serializers.ValidationError("This permission is already assigned to this user.")
        return data
    
    def get_user(self, obj):
        return {
            "id": obj.user_id.id,
            "username": obj.user_id.username,
            "email": obj.user_id.email,
            "first_name": obj.user_id.first_name,
            "last_name": obj.user_id.last_name,
            "phone": obj.user_id.phone
        }

    def get_permission(self, obj):
        return {
            "id": obj.permission_id.id,
            "permission_name": obj.permission_id.permission_name,
            "description": obj.permission_id.description
        }

    def get_perm_assigned_by(self, obj):
        return {
            "id": obj.assigned_by.id,
            "username": obj.assigned_by.username,
            "email": obj.assigned_by.email,
            "first_name": obj.assigned_by.first_name,
            "last_name": obj.assigned_by.last_name,
            "phone": obj.assigned_by.phone
        } if obj.assigned_by else None


# Serializer for AssignRoleToUser
class AssignRoleToUserSerializer(serializers.ModelSerializer):
    """
    Serializer for assigning a role to a user.
    Converts model instances to JSON and validates incoming data for the AssignRoleToUser model.
    """

    user = serializers.SerializerMethodField()
    role = serializers.SerializerMethodField()
    role_assigned_by = serializers.SerializerMethodField()

    class Meta:
        model = AssignRoleToUser
        fields = ['id', 'user_id', 'role_id', 'user', 'role', 'role_assigned_by']
        extra_kwargs = {
            'user_id': {'write_only': True},
            'role_id': {'write_only': True}
        }
    
    def validate(self, data):
        # Check if a similar assignment already exists
        if AssignRoleToUser.objects.filter(user_id=data['user_id'], role_id=data['role_id']).exists():
            raise serializers.ValidationError("This role is already assigned to this user.")
        return data
    
    def get_user(self, obj):
        return {
            "id": obj.user_id.id,
            "username": obj.user_id.username,
            "email": obj.user_id.email,
            "first_name": obj.user_id.first_name,
            "last_name": obj.user_id.last_name,
            "phone": obj.user_id.phone
        }

    def get_role(self, obj):
        return {
            "id": obj.role_id.id,
            "role_name": obj.role_id.role_name,
            "description": obj.role_id.description
        }

    def get_role_assigned_by(self, obj):
        return {
            "id": obj.assigned_by.id,
            "username": obj.assigned_by.username,
            "email": obj.assigned_by.email,
            "first_name": obj.assigned_by.first_name,
            "last_name": obj.assigned_by.last_name,
            "phone": obj.assigned_by.phone
        } if obj.assigned_by else None


# Serializer for AssignPermissionToRole
class AssignPermissionToRoleSerializer(serializers.ModelSerializer):
    """
    Serializer for assigning a permission to a role.
    Converts model instances to JSON and validates incoming data for the AssignPermissionToRole model.
    """

    permission = serializers.SerializerMethodField()
    role = serializers.SerializerMethodField()
    perm_assigned_by = serializers.SerializerMethodField()


    class Meta:
        model = AssignPermissionToRole
        fields = ['id', 'role_id', 'permission_id', 'permission', 'role', 'perm_assigned_by']
        extra_kwargs = {
            'permission_id': {'write_only': True},
            'role_id': {'write_only': True}
        }
    
    def validate(self, data):
        # Check if a similar assignment already exists
        if AssignPermissionToRole.objects.filter(permission_id=data['permission_id'], role_id=data['role_id']).exists():
            raise serializers.ValidationError("This permission is already assigned to this role.")
        return data
    
    def get_permission(self, obj):
        return {
            "id": obj.permission_id.id,
            "permission_name": obj.permission_id.permission_name,
            "description": obj.permission_id.description
        }

    def get_role(self, obj):
        return {
            "id": obj.role_id.id,
            "role_name": obj.role_id.role_name,
            "description": obj.role_id.description
        }

    def get_perm_assigned_by(self, obj):
        return {
            "id": obj.assigned_by.id,
            "username": obj.assigned_by.username,
            "email": obj.assigned_by.email,
            "first_name": obj.assigned_by.first_name,
            "last_name": obj.assigned_by.last_name,
            "phone": obj.assigned_by.phone
        } if obj.assigned_by else None


# Serializer for AssignPermissionToApplication
class AssignPermissionToApplicationSerializer(serializers.ModelSerializer):
    """
    Serializer for assigning a permission to a application.
    Converts model instances to JSON and validates incoming data for the AssignPermissionToRole model.
    """

    permission = serializers.SerializerMethodField()
    app = serializers.SerializerMethodField()
    perm_assigned_by = serializers.SerializerMethodField()

    class Meta:
        model = AssignPermissionApplication
        fields = ['id', 'application_id', 'permission_id', 'permission', 'app', 'perm_assigned_by']
        extra_kwargs = {
            'permission_id': {'write_only': True},
            'application_id': {'write_only': True}
        }
    
    def validate(self, data):
        # Check if a similar assignment already exists
        if AssignPermissionApplication.objects.filter(permission_id=data['permission_id'], application_id=data['application_id']).exists():
            raise serializers.ValidationError("This permission is already assigned to an this application.")
        return data

    def get_permission(self, obj):
        return {
            "id": obj.permission_id.id,
            "permission_name": obj.permission_id.permission_name,
            "description": obj.permission_id.description
        }

    def get_app(self, obj):
        return {
            "id": obj.application_id.id,
            "application_name": obj.application_id.application_name,
            "description": obj.application_id.description
        }

    def get_perm_assigned_by(self, obj):
        return {
            "id": obj.assigned_by.id,
            "username": obj.assigned_by.username,
            "email": obj.assigned_by.email,
            "first_name": obj.assigned_by.first_name,
            "last_name": obj.assigned_by.last_name,
            "phone": obj.assigned_by.phone
        } if obj.assigned_by else None


class UserDetailSerializer(serializers.ModelSerializer):

    """
    Serializer to customize get user informations with his role and permissions.
    """

    roles = serializers.SerializerMethodField()
    permissions = serializers.SerializerMethodField()

    user_created_by = serializers.SerializerMethodField()
    user_updated_by = serializers.SerializerMethodField()

    class Meta:
        model = CustomUser
        fields = ['id', 'email', 'username', 'first_name', 'last_name', 'phone', 'is_staff', 'is_active', 'is_superuser', 'user_created_by', 'user_updated_by', 'roles', 'permissions']

    def get_roles(self, obj):
        # Récupérer les rôles assignés à l'utilisateur
        assigned_roles = AssignRoleToUser.objects.filter(user_id=obj).select_related('role_id')
        return RoleWithPermissionsSerializer([role.role_id for role in assigned_roles], many=True).data

    def get_permissions(self, obj):
        # Récupérer les permissions directement assignées à l'utilisateur
        assigned_permissions = AssignPermissionToUser.objects.filter(user_id=obj).select_related('permission_id')
        return PermissionSerializer([perm.permission_id for perm in assigned_permissions], many=True).data
    
    def get_user_created_by(self, obj):
        return {
            "id": obj.created_by.id,
            "username": obj.created_by.username,
            "email": obj.created_by.email,
            "first_name": obj.created_by.first_name,
            "last_name": obj.created_by.last_name,
            "phone": obj.created_by.phone
        } if obj.created_by else None
    
    def get_user_updated_by(self, obj):
        return {
            "id": obj.updated_by.id,
            "username": obj.updated_by.username,
            "email": obj.updated_by.email,
            "first_name": obj.updated_by.first_name,
            "last_name": obj.updated_by.last_name,
            "phone": obj.updated_by.phone
        } if obj.updated_by else None


class RoleWithPermissionsSerializer(serializers.ModelSerializer):
    permissions = serializers.SerializerMethodField()

    class Meta:
        model = Role
        fields = ['id', 'role_name', 'description', 'permissions']

    def get_permissions(self, obj):
        # Retrieve role permissions
        role_permissions = AssignPermissionToRole.objects.filter(role_id=obj).select_related('permission_id')
        return PermissionSerializer([perm.permission_id for perm in role_permissions], many=True).data

