from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from api_users.models import AssignPermissionToUser, AssignRoleToUser, AssignPermissionToRole


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Serializer to customize the token response by including user information.
    """

    def validate(self, attrs):
        # Call the parent validate method to get the tokens
        data = super().validate(attrs)

        # Add custom user information to the response
        user = self.user
        assigned_permissions = AssignPermissionToUser.objects.filter(user_id=user).select_related('permission_id')
        assigned_roles = AssignRoleToUser.objects.filter(user_id=user).select_related('role_id')

        # Serialize the permissions using a custom serializer
        permissions = [
            {
                "id": perm.permission_id.id,
                "permission_name": perm.permission_id.permission_name,
                "description": perm.permission_id.description,
            }
            for perm in assigned_permissions
        ]

        # Serialize the role using a custom serializer
        # Format roles with their associated permissions

        roles = []

        for role_assignment in assigned_roles:
            role = role_assignment.role_id
            # Get permissions assigned to this role
            role_permissions = AssignPermissionToRole.objects.filter(role_id=role).select_related('permission_id')

            permissions = [
                {
                    "id": perm.permission_id.id,
                    "permission_name": perm.permission_id.permission_name,
                    "description": perm.permission_id.description
                }
                for perm in role_permissions
            ]

            roles.append({
                "id": role.id,
                "role_name": role.role_name,
                "permissions": permissions
            })

        data.update({
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "roles": roles,
                "permissions": permissions,
            }
        })

        return data

