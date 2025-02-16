from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
from django.utils.translation import gettext_lazy as _
from rest_framework_simplejwt.tokens import RefreshToken

from django.core.exceptions import ValidationError
import uuid
import re



class CustomUserManager(BaseUserManager):
    """
    Custom manager for User model to handle user creation and superuser creation.
    """

    def create_user(self, email, password=None, **extra_fields):
        """
        Creates and returns a user with an email, username, and password.
        
        Args:
            email (str): The email address of the user.
            username (str): The username of the user.
            password (str, optional): The password of the user.
            extra_fields (dict, optional): Extra fields to be added to the user.

        Returns:
            User: A new user instance.
        """
        if not email:
            raise ValueError(_('The Email field must be set'))
        
        if not password:
            raise ValueError(_('The Password field must be set'))

        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)  # Password is hashed before saving
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """
        Creates and returns a superuser with an email, username, and password.
        
        Args:
            email (str): The email address of the superuser.
            username (str): The username of the superuser.
            password (str, optional): The password of the superuser.
            extra_fields (dict, optional): Extra fields to be added to the superuser.

        Returns:
            User: A new superuser instance.
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        return self.create_user(email, password, **extra_fields)


class CustomUser(AbstractUser):
    """
    Custom User model to handle user authentication and additional fields such as phone, reset token, etc.

    Attributes:
        id (UUIDField): Unique identifier for the user.
        email (EmailField): Unique email address for the user.
        username (CharField): Unique username for the user.
        first_name (CharField): First name of the user.
        last_name (CharField): Last name of the user.
        phone (CharField): Phone number of the user.
        is_active (BooleanField): Flag to indicate if the user is active.
        is_staff (BooleanField): Flag to indicate if the user is a staff member.
        is_superuser (BooleanField): Flag to indicate if the user is a superuser.
        is_admin (BooleanField): Flag to indicate if the user is admin.
        date_joined (DateTimeField): Timestamp of when the user joined.
        password (CharField): The user's password, stored securely as a hash.
        reset_token (CharField): Token used for password reset, sent to the user for identity verification.
        reset_token_expire (DateTimeField): Expiration date and time of the reset token.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(_("email address"), unique=True, max_length=255)
    username = models.CharField(_("username"), max_length=100, unique=True)
    first_name = models.CharField(_("first name"), max_length=100)
    last_name = models.CharField(_("last name"), max_length=100, blank=True)
    phone = models.CharField(_("phone"), max_length=50, blank=True, null=True)
    is_active = models.BooleanField(_("active"), default=False)
    is_staff = models.BooleanField(_("staff status"), default=False)
    is_admin = models.BooleanField(_("admin status"), default=False)
    is_superuser = models.BooleanField(default=False)
    date_joined = models.DateTimeField(_("date joined"), auto_now_add=True)
    password = models.CharField(_("password"), max_length=255)
    reset_token = models.CharField(_("reset token"), max_length=255, blank=True, null=True)
    reset_token_expire = models.DateTimeField(_("reset token expire"), blank=True, null=True)

    created_by = models.ForeignKey(
        "self",
        on_delete=models.SET_NULL,
        related_name="user_created_by",
        help_text="User who created this user.",
        null=True,
        blank=True,
    )
    updated_by = models.ForeignKey(
        "self",
        on_delete=models.SET_NULL,
        related_name="user_updated_by",
        null=True,
        blank=True,
        help_text="User who last updated this user.",
    )

    
    # username = None
    # phone_number = models.CharField(max_length=15, blank=True, null=True)
    # email = models.EmailField(_("email address"), unique=True)

    USERNAME_FIELD = "username"
    REQUIRED_FIELDS = ["email", "first_name"]

    objects = CustomUserManager()

    def __str__(self):
        """
        String representation of the User instance, returns the username.
        
        Returns:
            str: The username of the user.
        """
        return self.username

    def save(self, *args, **kwargs):
        """
        Saves the user instance
        """
        super().save(*args, **kwargs)
    
    class Meta:
        ordering = ['-date_joined']


# --- Role Model ---
class Role(models.Model):
    """
    Represents a role in the system, including its name, description, status, 
    creation and update details, and references to the user responsible for 
    its creation or last update.

    Attributes:
        id (UUIDField): Unique identifier for the role.
        role_name (CharField): The name of the role, unique and alphanumeric.
        description (TextField): Detailed description of the role's responsibilities and privileges.
        is_active (BooleanField): Indicates whether the role is active or inactive.
        date_created (DateTimeField): Timestamp of the role's creation.
        date_updated (DateTimeField): Timestamp of the last update to the role.
        created_by (ForeignKey): References the user who created the role.
        updated_by (ForeignKey): References the user who last updated the role.
        display_name
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    role_name = models.CharField(
        max_length=100,
        unique=True,
        help_text="Unique name of the role, allowing only alphanumeric characters, dashes, and underscores.",
        default="role_name"
    )
    display_name = models.CharField(
        max_length=100,
        null=True
    )
    description = models.TextField(
        max_length=255,
        blank=True,
        null=True,
        help_text="Detailed description of the role's responsibilities and privileges."
    )
    is_active = models.BooleanField(
        default=True,
        help_text="Indicates whether the role is active (true) or inactive (false)."
    )
    date_created = models.DateTimeField(
        auto_now_add=True,
        help_text="Timestamp indicating when the role was created."
    )
    date_updated = models.DateTimeField(
        auto_now=True,
        help_text="Timestamp indicating the last time the role was updated."
    )
    created_by = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        related_name="role_created_by",
        help_text="User who created this role.",
        null=True,
        blank=True,
    )
    updated_by = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        related_name="role_updated_by",
        null=True,
        blank=True,
        help_text="User who last updated this role.",
    )

    def __str__(self):
        return self.role_name

    class Meta:
        verbose_name = "Role"
        verbose_name_plural = "Roles"
        ordering = ['-date_created']



# --- Permission Model ---
class Permission(models.Model):
    """
    Represents a permission in the system, defining specific rights or actions 
    that a user can perform. Permissions can be activated or deactivated, and 
    their creation and update metadata is tracked.

    Attributes:
        id (AutoField): Primary key, a unique integer identifier for each permission.
        permission_name (CharField): A unique, human-readable name for the permission.
        is_active (BooleanField): Indicates whether the permission is active (True) or inactive (False).
        display_name
        description (TextField): A brief description of the permission's purpose and scope.
        date_created (DateTimeField): Timestamp when the permission was created.
        date_updated (DateTimeField): Timestamp when the permission was last updated.
        created_by (ForeignKey): User who created the permission.
        updated_by (ForeignKey): User who last updated the permission (nullable).
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    permission_name = models.CharField(
        max_length=100,
        unique=True,
        help_text="Unique name for the permission, allowing only alphanumeric characters, dashes, and underscores.",
        default="perm_name"
    )
    display_name = models.CharField(
        max_length=100,
        null=True
    )
    is_active = models.BooleanField(
        default=True,
        help_text="Indicates whether the permission is active (True) or inactive (False)."
    )
    description = models.TextField(
        max_length=255,
        help_text="A detailed description of the permission's purpose and scope.",
        blank=True,
        null=True
    )
    date_created = models.DateTimeField(
        auto_now_add=True,
        help_text="The date and time when the permission was created."
    )
    date_updated = models.DateTimeField(
        auto_now=True,
        help_text="The date and time when the permission was last updated."
    )
    created_by = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        related_name="permission_created_by",
        help_text="The user who created this permission.",
        null=True,
        blank=True,
    )
    updated_by = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        related_name="permission_updated_by",
        null=True,
        blank=True,
        help_text="The user who last updated this permission."
    )

    def __str__(self):
        return self.permission_name

    class Meta:
        verbose_name = "Permission"
        verbose_name_plural = "Permissions"
        ordering = ['-date_created']


# --- Application Model ---
class Application(models.Model):
    """
    Represents an application or service within the system. This model provides
    information about the application, including its name, description, URL, status,
    and metadata for creation and updates.

    Attributes:
        id (AutoField): Primary key, a unique integer identifier for each application.
        application_name (CharField): The name of the application, used for identification.
        description (TextField): Detailed description of the application's purpose or functionality.
        url (URLField): URL to access or locate the application (mandatory).
        is_active (BooleanField): Indicates the current status of the application (active/inactive).
        date_created (DateTimeField): The date and time when the application was created.
        date_modified (DateTimeField): The date and time when the application was last updated.
        created_by (ForeignKey): The user who created the application (non-nullable).
        updated_by (ForeignKey): The user who last updated the application (nullable).
        image (CharField): Optional field for storing an image reference for the application.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    application_name = models.CharField(
        max_length=255,
        unique=True,
        help_text="Name of the application, used for identification (must be unique)."
    )
    description = models.TextField(
        max_length=255,
        blank=True,
        null=True,
        help_text="Detailed description of the application's purpose or functionality."
    )
    url = models.URLField(
        max_length=255,
        unique=True,
        help_text="URL to access or locate the application (mandatory)."
    )
    is_active = models.BooleanField(
        default=True,
        help_text="Indicates whether the application is active (True) or inactive (False)."
    )
    date_created = models.DateTimeField(
        auto_now_add=True,
        help_text="The date and time when the application was created."
    )
    date_modified = models.DateTimeField(
        auto_now=True,
        help_text="The date and time when the application was last updated."
    )
    created_by = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        related_name="app_created_by",
        help_text="The user who created this application (non-nullable).",
        null=True,
        blank=True,
    )
    updated_by = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        related_name="app_updated_by",
        null=True,
        blank=True,
        help_text="The user who last updated this application (nullable)."
    )
    image = models.CharField(
        max_length=500,
        blank=True,
        null=True,
        help_text="Optional field for storing an image reference for the application."
    )

    def __str__(self):
        return self.application_name

    class Meta:
        verbose_name = "Application"
        verbose_name_plural = "Applications"
        ordering = ['-date_created']

# --- Assign Permission to Users ---
class AssignPermissionToUser(models.Model):
    """
    Represents the assignment of a specific permission to a user within the system.
    Tracks which user has been assigned a permission, who assigned it, and when the assignment occurred.

    Attributes:
        id (UUIDField): Primary key, uniquely identifies each assignment.
        user_id (ForeignKey): The user to whom the permission is assigned (foreign key to the user table).
        permission_id (ForeignKey): The permission assigned to the user (foreign key to the permission table).
        assigned_by (ForeignKey): The administrator or user who assigned the permission (foreign key to the user table).
        date_assigned (DateTimeField): The date and time the permission was assigned.
    """
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text="Unique identifier for each permission assignment."
    )
    user_id = models.ForeignKey(
        CustomUser,
        on_delete=models.CASCADE,
        related_name="user_recipiant",
        help_text="The user to whom the permission is assigned (must exist in the user table)."
    )
    permission_id = models.ForeignKey(
        Permission,
        on_delete=models.CASCADE,
        related_name="permission_attached_to_user",
        help_text="The permission assigned to the user (must exist in the permission table)."
    )
    assigned_by = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        related_name="permissions_user_assigned_by",
        help_text="The user who assigned the permission (must exist in the user table).",
        null=True,
    )
    date_assigned = models.DateTimeField(
        auto_now_add=True,
        help_text="The date and time when the permission was assigned."
    )

    def __str__(self):
        return f"Permission {self.permission_id.permission_name} assigned to {self.user_id.username}"

    class Meta:
        verbose_name = "Assign Permission to User"
        verbose_name_plural = "Assign Permissions to Users"
        ordering = ['-date_assigned']

# --- Assign Roles to Users ---
class AssignRoleToUser(models.Model):
    """
    Represents the assignment of a specific role to a user within the system.
    Tracks which user has been assigned a role, who assigned it, and when the assignment occurred.

    Attributes:
        id (UUIDField): Primary key, a unique identifier for each role assignment.
        user_id (ForeignKey): The user to whom the role is assigned (foreign key to the user table).
        role_id (ForeignKey): The role assigned to the user (foreign key to the role table).
        assigned_by (ForeignKey): The user or administrator who assigned the role (foreign key to the user table).
        date_assigned (DateTimeField): The date and time when the role was assigned.
    """
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text="Unique identifier for each role assignment."
    )
    user_id = models.ForeignKey(
        CustomUser,
        on_delete=models.CASCADE,
        related_name="user_recipiant_role",
        help_text="The user to whom the role is assigned (must exist in the user table)."
    )
    role_id = models.ForeignKey(
        Role,
        on_delete=models.CASCADE,
        related_name="role_transmitted_user",
        help_text="The role assigned to the user (must exist in the role table)."
    )
    assigned_by = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        related_name="role_user_assigned_by",
        help_text="The user or administrator who assigned the role (must exist in the user table).",
        null=True,
    )
    date_assigned = models.DateTimeField(
        auto_now_add=True,
        help_text="The date and time when the role was assigned."
    )

    def __str__(self):
        return f"Role: {self.role_id.role_name} assigned to {self.user_id.username}"

    class Meta:
        verbose_name = "Assign Role to User"
        verbose_name_plural = "Assign Roles to Users"
        ordering = ['-date_assigned']
    


# --- Assign Permissions to Roles ---
class AssignPermissionToRole(models.Model):
    """
    Represents the assignment of a specific permission to a role within the system.
    Tracks which permission is assigned to which role, who assigned it, and when the assignment occurred.

    Attributes:
        id (UUIDField): Primary key, a unique identifier for each role-permission assignment.
        role_id (ForeignKey): The role to which the permission is assigned (foreign key to the Role table).
        permission_id (ForeignKey): The permission assigned to the role (foreign key to the Permission table).
        assigned_by (ForeignKey): The user or administrator who assigned the permission (foreign key to the User table).
        date_assigned (DateTimeField): The date and time when the permission was assigned.
    """
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text="Unique identifier for each role-permission assignment."
    )
    role_id = models.ForeignKey(
        Role,
        on_delete=models.CASCADE,
        related_name="role_recipiant_permissions",
        help_text="The role to which the permission is assigned (must exist in the Role table)."
    )
    permission_id = models.ForeignKey(
        Permission,
        on_delete=models.CASCADE,
        related_name="permission_attached_role",
        help_text="The permission assigned to the role (must exist in the Permission table)."
    )
    assigned_by = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        related_name="role_permission_assigned_by",
        help_text="The user or administrator who assigned the permission (must exist in the User table).",
        null=True,
    )
    date_assigned = models.DateTimeField(
        auto_now_add=True,
        help_text="The date and time when the permission was assigned."
    )

    def __str__(self):
        return f"Permission: {self.permission_id.permission_name} assigned to Role: {self.role_id.role_name}"

    class Meta:
        verbose_name = "Assign Permission Role"
        verbose_name_plural = "Assign Permissions Role"
        ordering = ['-date_assigned']

# --- Assign Permissions to Applications ---
class AssignPermissionApplication(models.Model):
    """
    Represents the assignment of a specific permission to an application within the system.
    Tracks which permission is assigned to which application, who assigned it, and when the assignment occurred.

    Attributes:
        id (UUIDField): Primary key, a unique identifier for each permission assignment.
        application_id (ForeignKey): The application to which the permission is assigned (foreign key to the application table).
        permission_id (ForeignKey): The permission assigned to the application (foreign key to the permission table).
        assigned_by (ForeignKey): The user or administrator who assigned the permission (foreign key to the user table).
        date_assigned (DateTimeField): The date and time when the permission was assigned.
    """
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text="Unique identifier for each permission assignment."
    )
    application_id = models.ForeignKey(
        Application,
        on_delete=models.CASCADE,
        related_name="application_recipiant_permission",
        help_text="The application to which the permission is assigned (must exist in the application table)."
    )
    permission_id = models.ForeignKey(
        Permission,
        on_delete=models.CASCADE,
        related_name="application_app_attached",
        help_text="The permission assigned to the application (must exist in the permission table)."
    )
    assigned_by = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        related_name="permissions_app_assigned_by",
        help_text="The user or administrator who assigned the permission (must exist in the user table).",
        null=True,
    )
    date_assigned = models.DateTimeField(
        auto_now_add=True,
        help_text="The date and time when the permission was assigned."
    )

    def __str__(self):
        return f"Permission: {self.permission_id.permission_name} assigned to Application: {self.application_id.application_name}"

    class Meta:
        verbose_name = "Assign Application Permission"
        verbose_name_plural = "Assign Application Permissions"
        ordering = ['-date_assigned']


class PasswordResetToken(models.Model):
    """
    Model representing a password reset token for a user.

    Attributes:
        id (UUIDField): The unique identifier for the token, automatically generated as a UUID.
        user_id (ForeignKey): A foreign key linking to the CustomUser model. Represents the user for whom the token is created.
        token (CharField): A unique token used for resetting the user's password.
        expiration (DateTimeField): The expiration date and time of the token, after which it becomes invalid.
    
    Methods:
        __str__(): Returns a string representation of the token, including the associated user's identifier.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_id = models.ForeignKey(
        CustomUser, 
        on_delete=models.CASCADE, 
        related_name='password_reset_token_user'
    )
    token = models.CharField(max_length=255, unique=True)
    expiration = models.DateTimeField()

    def __str__(self):
        return f"PasswordResetToken for {self.user_id.username}"

    class Meta:
        verbose_name = "Password Reset Token"
        verbose_name_plural = "Password Reset Tokens"
    
class UserToken(models.Model):
    """
    Model representing a refresh token for a user.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        CustomUser, 
        on_delete=models.SET_NULL,
        null=True, 
        blank=True
    )
    refresh_token = models.TextField()
    access_token = models.TextField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_valid(self):
        # Check if the refresh token is still valid
        try:
            token = RefreshToken(self.refresh_token)
            return True
        except Exception:
            return False

class UserTokenBlacklisted(models.Model):
    """
    Model representing a refresh token blacklisted for a user.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        CustomUser, 
        on_delete=models.SET_NULL,
        null=True, 
        blank=True
    )
    refresh_token = models.TextField()
    access_token = models.TextField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

