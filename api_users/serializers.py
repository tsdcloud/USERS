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

import re, uuid
from django.utils.translation import gettext_lazy as _
from django.utils.timezone import now, timedelta
from .utils import validate_password, generate_random_chain
from django.core.mail import send_mail
from django.db import transaction

BERP_FRONT_END_URL = "https://berp.bfcgroupsa.com"


class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for the User model, used for creating and updating users.
    """
    roles = serializers.SerializerMethodField()
    permissions = serializers.SerializerMethodField()

    user_created_by = serializers.SerializerMethodField()
    user_updated_by = serializers.SerializerMethodField()

    class Meta:
        model = CustomUser
        fields = ['id', 'email', 'username', 'first_name', 'last_name', 'phone', 'is_staff', 'is_active', 'is_admin', 'is_superuser', 'user_created_by', 'user_updated_by', 'roles', 'permissions']
        extra_kwargs = {
            'password': {'write_only': True},
        }
    
    def get_roles(self, obj):
        # Retrieve user-assigned roles
        assigned_roles = AssignRoleToUser.objects.filter(user_id=obj, role_id__is_active=True).select_related('role_id')
        return RoleWithPermissionsSerializer([role.role_id for role in assigned_roles], many=True).data

    def get_permissions(self, obj):
        # Retrieve permissions directly assigned to the user
        assigned_permissions = AssignPermissionToUser.objects.filter(user_id=obj, permission_id__is_active=True).select_related('permission_id')
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
    
    # Fields validation
    def validate_email(self, value):
        """
        Validates that the email contains only allowed characters.
        """
        email_regex = r'^[A-Za-z0-9._@\-]+$'
        if not value:
            raise serializers.ValidationError(_("Email cannot be empty"))
        if not re.match(email_regex, value):
            raise serializers.ValidationError(_("The email address contains invalid characters. Only letters, numbers, and '@', '_', '-', '.' are allowed."))
        # Ignore uniqueness validation for PATCH requests
        if self.context.get('request', None) and self.context['request'].method != "PATCH":
            if CustomUser.objects.filter(email=value).exists():
                raise serializers.ValidationError(_("Email is already taken"))
        return value

    def validate_username(self, value):
        """
        Validates that the username contains only allowed characters.
        """
        if not value:
            raise serializers.ValidationError(_("Username cannot be empty"))
        if not re.match(r'^[A-Za-z0-9._]+$', value):
            raise serializers.ValidationError(_("Username can only contain letters, numbers, dots (.) and underscores (_)"))
        # Ignore uniqueness validation for PATCH requests
        if self.context.get('request', None) and self.context['request'].method != "PATCH":
            if CustomUser.objects.filter(username=value).exists():
                raise serializers.ValidationError(_("Username is already taken"))
        return value

    def validate_first_name(self, value):
        """
        Validates that the first name contains only letters.
        """
        if not value:
            raise serializers.ValidationError(_("First name cannot be empty"))
        if not re.match(r"^[A-Za-zà-ÿÀ-Ÿ' -]+$", value):
            raise serializers.ValidationError(_("firstname can only contain letters, spaces, apostrophes, and hyphens"))
        return value

    def validate_last_name(self, value):
        """
        Validates that the last name contains only allowed characters.
        """
        if value and not re.match(r"^[A-Za-zà-ÿÀ-Ÿ' -]+$", value):
            raise serializers.ValidationError(_("Last name can only contain letters, spaces, apostrophes, and hyphens"))
        return value

    def validate_phone(self, value):
        """
        Validates that the phone number contains only allowed characters.
        """
        if value:
            if len(value) < 9:
                raise serializers.ValidationError(_("Phone number must be at least 9 characters long"))
            if not re.match(r'^[0-9\-]+$', value):
                raise serializers.ValidationError(_("Phone number can only contain digits and hyphens"))
        return value
    
    def create(self, validated_data):

        # Generate a random reset token
        reset_token = str(uuid.uuid4())
        validated_data['reset_token'] = reset_token
        validated_data['reset_token_expire'] = now() + timedelta(hours=24)

        # Handle password separately
        password = validated_data.pop('password', None)
        user = CustomUser(**validated_data)
        if password:
            user.set_password(password)
        else:
            # Generate a random password if not provided
            user.set_password(generate_random_chain(12))

        # Construct the reset URL
        reset_url = f"{BERP_FRONT_END_URL}/confirmPassword/?token={reset_token}"

        # Send email with the reset link
        email = validated_data['email']
        first_name = validated_data['first_name']
        try:
            send_mail(
                subject="Set Your Password",
                message=f"Hi {first_name},\nPlease click the link below to set your password:\n{reset_url}",
                from_email="no-reply@bfcgroupsa.com",
                recipient_list=[email],
                fail_silently=False,
                html_message=f"""
                    <p>Hi {first_name},</p>
                    <p>Please click the link below to set your password:</p>
                    <a href="{reset_url}">Set Your Password</a>
                """
            )
        except Exception as e:
            raise serializers.ValidationError({"email_error": _("Failed to send email. Please try again.")})
        
        user.save()
        return user
    
    def update(self, instance, validated_data):
        validated_data.pop('password', None)
        return super().update(instance, validated_data)


class PermissionSerializer(serializers.ModelSerializer):
    """
    Serializer to create, update, and retrieve permissions.

    - Allows the creation and updating of permission names, descriptions, and active status.
    """

    # perm_created_by = serializers.SerializerMethodField()
    # perm_updated_by = serializers.SerializerMethodField()
    
    class Meta:
        model = Permission
        fields = ['id', 'permission_name', 'display_name', 'description', 'is_active']
        read_only_fields = ['created_by', 'date_created']
    
    # def get_perm_created_by(self, obj):
    #     return {
    #         "id": obj.created_by.id,
    #         "username": obj.created_by.username,
    #         "email": obj.created_by.email,
    #         "first_name": obj.created_by.first_name,
    #         "last_name": obj.created_by.last_name,
    #         "phone": obj.created_by.phone
    #     } if obj.created_by else None
    
    # def get_perm_updated_by(self, obj):
    #     return {
    #         "id": obj.updated_by.id,
    #         "username": obj.updated_by.username,
    #         "email": obj.updated_by.email,
    #         "first_name": obj.updated_by.first_name,
    #         "last_name": obj.updated_by.last_name,
    #         "phone": obj.updated_by.phone
    #     } if obj.updated_by else None

    # Fields validation
    # def validate_permission_name(self, value):
    #     """
    #     Validates permission name.
    #     """
    #     if not value:
    #         raise serializers.ValidationError(_("permission name cannot be empty"))
    #     if Permission.objects.filter(permission_name=value).exists():
    #         raise serializers.ValidationError(_("permission with this name already exist"))
    #     if not re.match(r'^[0-9\-]+$', value):
    #         raise serializers.ValidationError(_("The permission field can only contain lowercase letters and underscores. Ex: can_change."))
    #     return value
    
    def validate_display_name(self, value):
        """
        Validates display name.
        """
        # permission_name = value
        if not value:
            raise serializers.ValidationError(_("display name cannot be empty"))
        if Permission.objects.filter(display_name=value).exists():
            raise serializers.ValidationError(_("permission with this display name already exist"))
        if not re.match(r'^[^_.]+$', value):
            raise serializers.ValidationError(_("the display name must not contain underscores (_) or dots (.)"))
        return value
    
    def create(self, validated_data):

        # Generate a random reset token
        validated_data['permission_name'] = validated_data['display_name'].replace(" ", "_").lower()

        if Permission.objects.filter(permission_name=validated_data['permission_name']).exists():
            raise serializers.ValidationError(_("permission with this name already exist"))

        perm = Permission(**validated_data)
        
        perm.save()
        return perm
    
    def update(self, instance, validated_data):
        if 'display_name' in validated_data:
            validated_data['permission_name'] = validated_data['display_name'].replace(" ", "_").lower()
        
        # Update instance fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        
        # Save the instance
        instance.save()
        return instance


class RoleSerializer(serializers.ModelSerializer):
    """
    Serializer to create, update, and retrieve roles.

    - Allows the creation and updating of role names, descriptions, and active status.
    """

    # role_created_by = serializers.SerializerMethodField()
    # role_updated_by = serializers.SerializerMethodField()

    class Meta:
        model = Role
        fields = ['id', 'role_name', 'display_name', 'description', 'is_active']
    
    # def get_role_created_by(self, obj):
    #     return {
    #         "id": obj.created_by.id,
    #         "username": obj.created_by.username,
    #         "email": obj.created_by.email,
    #         "first_name": obj.created_by.first_name,
    #         "last_name": obj.created_by.last_name,
    #         "phone": obj.created_by.phone
    #     } if obj.created_by else None
    
    # def get_role_updated_by(self, obj):
    #     return {
    #         "id": obj.updated_by.id,
    #         "username": obj.updated_by.username,
    #         "email": obj.updated_by.email,
    #         "first_name": obj.updated_by.first_name,
    #         "last_name": obj.updated_by.last_name,
    #         "phone": obj.updated_by.phone
    #     } if obj.updated_by else None

    # Fields validation
    # def validate_role_name(self, value):
    #     """
    #     Validates role name.
    #     """
    #     if not value:
    #         raise serializers.ValidationError(_("role name cannot be empty"))
    #     if Role.objects.filter(role_name=value).exists():
    #         raise serializers.ValidationError(_("role with this name already exist"))
    #     if not re.match(r'^[0-9\-]+$', value):
    #         raise serializers.ValidationError(_("The role field can only contain lowercase letters and underscores. Ex: can_add_all."))
    #     return value
    
    def validate_display_name(self, value):
        """
        Validates display name.
        """
        if not value:
            raise serializers.ValidationError(_("display name cannot be empty"))
        if Role.objects.filter(display_name=value).exists():
            raise serializers.ValidationError(_("role with this display name already exist"))
        if not re.match(r'^[^_.]+$', value):
            raise serializers.ValidationError(_("the display name must not contain underscores (_) or dots (.),"))
        return value
    
    def create(self, validated_data):

        # Generate a random reset token
        validated_data['role_name'] = validated_data['display_name'].replace(" ", "_").lower()

        if Role.objects.filter(role_name=validated_data['role_name']).exists():
            raise serializers.ValidationError(_("role with this name already exist"))

        role = Role(**validated_data)
        
        role.save()
        return role
    
    def update(self, instance, validated_data):
        if 'display_name' in validated_data:
            validated_data['role_name'] = validated_data['display_name'].replace(" ", "_").lower()
        
        # Update instance fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        
        # Save the instance
        instance.save()
        return instance


class ApplicationSerializer(serializers.ModelSerializer):
    """
    Serializer to create, update, and retrieve applications.

    - Allows the creation and updating of application name, description, URL, and active status.
    """

    app_created_by = serializers.SerializerMethodField()
    app_updated_by = serializers.SerializerMethodField()

    permissions = serializers.SerializerMethodField()

    class Meta:
        model = Application
        fields = ['id', 'application_name', 'description', 'url', 'app_created_by', 'app_updated_by', 'is_active', 'permissions']
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
    
    # Fields validation
    def validate_application_name(self, value):
        """
        Validates application name.
        """
        if not value:
            raise serializers.ValidationError(_("application name cannot be empty"))
        if Permission.objects.filter(permission_name=value).exists():
            raise serializers.ValidationError(_("application with this name already exist"))
        return value
    
    def get_permissions(self, obj):
        # Retrieve user permissions
        role_permissions = AssignPermissionApplication.objects.filter(application_id=obj, permission_id__is_active=True).select_related('permission_id')
        return PermissionSerializer([perm.permission_id for perm in role_permissions], many=True).data



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
            perm = AssignPermissionToUser.objects.filter(permission_id=data['permission_id'], user_id=data['user_id']).first().permission_id.display_name
            user = AssignPermissionToUser.objects.filter(permission_id=data['permission_id'], user_id=data['user_id']).first().user_id.first_name
            raise serializers.ValidationError(f"This permission '{perm}' is already assigned to this user '{user}'.")
            # raise serializers.ValidationError("This permission is already assigned to this user.")
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
            'display_name': obj.permission_id.display_name,
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
            role = AssignRoleToUser.objects.filter(role_id=data['role_id'], user_id=data['user_id']).first().role_id.display_name
            user = AssignRoleToUser.objects.filter(role_id=data['role_id'], user_id=data['user_id']).first().user_id.first_name
            raise serializers.ValidationError(f"This role '{role}' is already assigned to this user '{user}'.")
            # raise serializers.ValidationError("This role is already assigned to this user.")
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
            'display_name': obj.role_id.display_name,
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
            # perm = AssignPermissionToRole.objects.filter(permission_id=data['permission_id'], role_id=data['role_id']).first().permission_id.permission_name
            # raise serializers.ValidationError(f"This permission '{perm}' is already assigned to this role.")
            raise serializers.ValidationError("This permission is already assigned to this role.")
        return data
    
    def get_permission(self, obj):
        return {
            "id": obj.permission_id.id,
            "permission_name": obj.permission_id.permission_name,
            'display_name': obj.permission_id.display_name,
            "description": obj.permission_id.description
        }

    def get_role(self, obj):
        return {
            "id": obj.role_id.id,
            "role_name": obj.role_id.role_name,
            'display_name': obj.role_id.display_name,
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
    

class AssignPermissionsToRoleSerializer(serializers.Serializer):
    role_id = serializers.UUIDField(required=True, format='hex_verbose', help_text="UUID's role.")
    permission_ids = serializers.ListField(
        child=serializers.UUIDField(format='hex_verbose'),
        required=True,
        allow_empty=False,
        help_text="List of permissions IDs to associate with the role."
    )

    def validate(self, data):
        role_id = data.get('role_id')

        role_instance = Role.objects.get(id=role_id)

        if not Role.objects.filter(id=role_id).exists():
            raise serializers.ValidationError({"role_id": "The specified role does not exist."})

        # Check that all permissions exist
        permission_ids = data.get('permission_ids', [])
        
        invalid_permissions = [
            perm_id for perm_id in permission_ids if not Permission.objects.filter(id=perm_id).exists()
        ]

        similars_assignment = []
        
        if invalid_permissions:
            raise serializers.ValidationError({
                "permission_ids": f"The following permission IDs are invalid : {invalid_permissions}"
            })
        
        for perm_id in permission_ids:
            permission_instance = Permission.objects.get(id=perm_id)
            # Check if a similar assignment already exists
            if AssignPermissionToRole.objects.filter(permission_id=permission_instance, role_id=role_instance).exists():
                similars_assignment.append(AssignPermissionToRole.objects.filter(role_id=role_instance, permission_id=permission_instance).first().permission_id.permission_name)
            
            # perm = AssignPermissionToRole.objects.filter(permission_id=data['permission_id'], role_id=data['role_id']).first().permission_id.permission_name
            # raise serializers.ValidationError(f"This permission '{perm}' is already assigned to this role.")
        
        if similars_assignment:
            permissions_str = ", ".join(similars_assignment)
            raise serializers.ValidationError(f"The following permissions: {permissions_str}, are already assigned to this role.")
            

        return data

    def create(self, validated_data):

        role_id = validated_data['role_id']
        permission_ids = validated_data['permission_ids']

        role_instance = Role.objects.get(id=role_id)

        # Using a transaction to guarantee data integrity
        with transaction.atomic():
            associations = []
            similars_assignment = []

            for perm_id in permission_ids:
                permission_instance = Permission.objects.get(id=perm_id)
                # Check if a similar assignment already exists
                if AssignPermissionToRole.objects.filter(permission_id=permission_instance, role_id=role_instance).exists():
                    similars_assignment.append(AssignPermissionToRole(role_id=role_instance, permission_id=permission_instance))
                
                associations.append(AssignPermissionToRole(role_id=role_instance, permission_id=permission_instance))
            
            # if

            # Creation in a single query
            AssignPermissionToRole.objects.bulk_create(associations, ignore_conflicts=True)

        return {"role_id": role_id, "permission_ids": permission_ids}


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
            perm = AssignPermissionApplication.objects.get(permission_id=data['permission_id'], application_id=data['application_id']).permission_id.display_name
            app = AssignPermissionApplication.objects.get(permission_id=data['permission_id'], application_id=data['application_id']).application_id.application_name
            raise serializers.ValidationError(f"This permission '{perm}' is already assigned to an this application '{app}'.")
            # raise serializers.ValidationError(f"This permission is already assigned to this application.")
        return data

    def get_permission(self, obj):
        return {
            "id": obj.permission_id.id,
            "permission_name": obj.permission_id.permission_name,
            "description": obj.permission_id.description,
            "display_name": obj.permission_id.display_name
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
        # Retrieve user-assigned roles
        assigned_roles = AssignRoleToUser.objects.filter(user_id=obj, role_id__is_active=True).select_related('role_id')
        return RoleWithPermissionsSerializer([role.role_id for role in assigned_roles], many=True).data

    def get_permissions(self, obj):
        # Retrieve permissions directly assigned to the user
        assigned_permissions = AssignPermissionToUser.objects.filter(user_id=obj, permission_id__is_active=True).select_related('permission_id')
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
        fields = ['id', 'role_name', 'display_name', 'description', 'is_active', 'permissions']

    def get_permissions(self, obj):
        # Retrieve role permissions
        role_permissions = AssignPermissionToRole.objects.filter(role_id=obj, permission_id__is_active=True).select_related('permission_id')
        return PermissionSerializer([perm.permission_id for perm in role_permissions], many=True).data

class UserWithPermissionsSerializer(serializers.ModelSerializer):
    permissions = serializers.SerializerMethodField()

    class Meta:
        model = CustomUser
        fields = ['id', 'username', 'permissions']

    def get_permissions(self, obj):
        # Retrieve user permissions
        role_permissions = AssignPermissionToUser.objects.filter(user_id=obj, permission_id__is_active=True).select_related('permission_id')
        return PermissionSerializer([perm.permission_id for perm in role_permissions], many=True).data

class UserWithRolesSerializer(serializers.ModelSerializer):
    roles = serializers.SerializerMethodField()

    class Meta:
        model = CustomUser
        fields = ['id', 'username', 'roles']

    def get_roles(self, obj):
        # Retrieve user_assigned roles
        assigned_roles = AssignRoleToUser.objects.filter(user_id=obj, role_id__is_active=True).select_related('role_id')
        return RoleWithPermissionsSerializer([role.role_id for role in assigned_roles], many=True).data
    
class ApplicationWithPermissionSerializer(serializers.ModelSerializer):
    permissions = serializers.SerializerMethodField()

    class Meta:
        model = Application
        fields = ['id', 'application_name', 'description', 'url', 'is_active', 'permissions']

    def get_permissions(self, obj):
        # Retrieve user permissions
        role_permissions = AssignPermissionApplication.objects.filter(application_id=obj, permission_id__is_active=True).select_related('permission_id')
        return PermissionSerializer([perm.permission_id for perm in role_permissions], many=True).data
