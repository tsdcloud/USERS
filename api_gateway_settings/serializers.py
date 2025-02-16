from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from api_users.models import AssignPermissionToUser, AssignRoleToUser, AssignPermissionToRole

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):

    """
    Serializer to customize the token response by including user information.
    """

    @classmethod
    def get_token(cls, user):
        # Get the default token
        token = super().get_token(user)
        
        # Add custom user information to the response
        assigned_permissions = AssignPermissionToUser.objects.filter(user_id=user, permission_id__is_active=True).select_related('permission_id')
        assigned_roles = AssignRoleToUser.objects.filter(user_id=user, role_id__is_active=True).select_related('role_id')

        # Serialize the permissions using a custom serializer
        permissions = [
            {
                "id": str(perm.permission_id.id),
                "permission_name": perm.permission_id.permission_name,
                "description": perm.permission_id.description,
                "is_active": perm.permission_id.is_active
            }
            for perm in assigned_permissions
        ]

        # Serialize the role using a custom serializer
        # Format roles with their associated permissions

        roles = []

        for role_assignment in assigned_roles:
            role = role_assignment.role_id
            # Get permissions assigned to this role
            role_permissions = AssignPermissionToRole.objects.filter(role_id=role, permission_id__is_active=True).select_related('permission_id')

            permissions = [
                {
                    "id": str(perm.permission_id.id),
                    "permission_name": perm.permission_id.permission_name,
                    "description": perm.permission_id.description,
                    "is_active": perm.permission_id.is_active
                }
                for perm in role_permissions
            ]

            roles.append({
                "id": str(role.id),
                "role_name": role.role_name,
                "is_active": role.is_active,
                "permissions": permissions
            })

        # Add custom claims to the token payload
        token['user'] = {
            "id": str(user.id),
            "username": user.username,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "is_admin": user.is_admin,
            "is_superuser": user.is_superuser,
            "is_staff": user.is_staff,
            "roles": roles,
            "permissions": permissions,
        }

        return token