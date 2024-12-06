from rest_framework import serializers
from .models import CustomUser, Permission, Role, Application, AssignPermissionToUser, AssignRoleToUser, AssignPermissionToRole, AssignPermissionApplication
from .utils import validate_password

class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for the User model, used for creating and updating users.
    """
    
    class Meta:
        model = CustomUser
        fields = ['id', 'email', 'username', 'first_name', 'last_name', 'phone', 'password']
        extra_kwargs = {
            'password': {'write_only': True},  # Password will not be returned in replies
            # 'created': {'read_only': True},    # The created field is read-only
        }

    def create(self, validated_data):
        """
        Override the create method to hash the password before saving the user.

        Create a new user.

        Args:
            validated_data: Data to create a user.

        Returns:
            CustomUser: The created user instance.
        """
        password = validated_data.pop('password', None)

        validate_password(password)

        user = CustomUser(**validated_data)
        if password:
            user.set_password(password)
        user.save()
        return user
    
    def update(self, instance, validated_data):
        """
        Update an existing user.

        Args:
            instance: The existing user instance.
            validated_data: Data to update the user.

        Returns:
            CustomUser: The updated user instance.
        """

        validated_data.pop('password', None)
        
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance


class PermissionSerializer(serializers.ModelSerializer):
    """
    Serializer to create, update, and retrieve permissions.

    - Allows the creation and updating of permission names, descriptions, and active status.
    """
    
    class Meta:
        model = Permission
        fields = ['id', 'permission_name', 'description', 'is_active', 'created_by', 'date_created']
        read_only_fields = ['created_by', 'date_created']


class RoleSerializer(serializers.ModelSerializer):
    """
    Serializer to create, update, and retrieve roles.

    - Allows the creation and updating of role names, descriptions, and active status.
    """

    class Meta:
        model = Role
        fields = ['id', 'role_name', 'description', 'is_active']
    

class ApplicationSerializer(serializers.ModelSerializer):
    """
    Serializer to create, update, and retrieve applications.

    - Allows the creation and updating of application name, description, URL, and active status.
    """

    class Meta:
        model = Application
        fields = ['id', 'application_name', 'description', 'url', 'is_active']
        read_only_fields = ['created_by', 'date_created']


# Serializer for AssignPermissionToUser
class AssignPermissionToUserSerializer(serializers.ModelSerializer):
    """
    Serializer for assigning a permission to a user.
    Converts model instances to JSON and validates incoming data for the AssignPermissionToUser model.
    """
    class Meta:
        model = AssignPermissionToUser
        fields = ['id', 'user_id', 'permission_id']
    
    def validate(self, data):
        # Check if a similar assignment already exists
        if AssignPermissionToUser.objects.filter(user_id=data['user_id'], permission_id=data['permission_id']).exists():
            raise serializers.ValidationError("This permission is already assigned to this user.")
        return data
    

class PermissionToUserListSerializer(serializers.ModelSerializer):
    """
    Serializer for listing permissions assigned to a user.
    Converts model instances to JSON for the AssignPermissionToUser model.
    """
    user = serializers.SerializerMethodField()
    permission = serializers.SerializerMethodField()
    perm_assigned_by = serializers.SerializerMethodField()

    class Meta:
        model = AssignPermissionToUser
        fields = ['id', 'user', 'permission', 'perm_assigned_by', 'date_assigned']

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
        }


# Serializer for AssignRoleToUser
class AssignRoleToUserSerializer(serializers.ModelSerializer):
    """
    Serializer for assigning a role to a user.
    Converts model instances to JSON and validates incoming data for the AssignRoleToUser model.
    """
    class Meta:
        model = AssignRoleToUser
        fields = ['id', 'user_id', 'role_id']
    
    def validate(self, data):
        # Check if a similar assignment already exists
        if AssignRoleToUser.objects.filter(user_id=data['user_id'], role_id=data['role_id']).exists():
            raise serializers.ValidationError("This role is already assigned to this user.")
        return data


# Serializer for AssignPermissionToRole
class AssignPermissionToRoleSerializer(serializers.ModelSerializer):
    """
    Serializer for assigning a permission to a role.
    Converts model instances to JSON and validates incoming data for the AssignPermissionToRole model.
    """
    class Meta:
        model = AssignPermissionToRole
        fields = ['id', 'role_id', 'permission_id']
    
    def validate(self, data):
        # Check if a similar assignment already exists
        if AssignPermissionToRole.objects.filter(permission_id=data['permission_id'], role_id=data['role_id']).exists():
            raise serializers.ValidationError("This permission is already assigned to this role.")
        return data


# Serializer for AssignPermissionToApplication
class AssignPermissionToApplicationSerializer(serializers.ModelSerializer):
    """
    Serializer for assigning a permission to a application.
    Converts model instances to JSON and validates incoming data for the AssignPermissionToRole model.
    """
    class Meta:
        model = AssignPermissionApplication
        fields = ['id', 'application_id', 'permission_id']
    
    def validate(self, data):
        # Check if a similar assignment already exists
        if AssignPermissionApplication.objects.filter(permission_id=data['permission_id'], application_id=data['application_id']).exists():
            raise serializers.ValidationError("This permission is already assigned to an this application.")
        return data




