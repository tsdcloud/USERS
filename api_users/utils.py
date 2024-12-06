from django.core.exceptions import ValidationError
import re
from django.utils.translation import gettext_lazy as _



def validate_password(password):
        """
        Validates that the password meets security requirements (length, uppercase, lowercase, number, special character).

        Args:
            password (str): The password to validate.

        Raises:
            ValidationError: If the password does not meet the requirements.
        """
        if len(password) < 8:
            raise ValidationError(_("Password must be at least 8 characters long"))
        if not re.search(r'[A-Z]', password):
            raise ValidationError(_("Password must contain at least one uppercase letter"))
        if not re.search(r'[a-z]', password):
            raise ValidationError(_("Password must contain at least one lowercase letter"))
        if not re.search(r'[0-9]', password):
            raise ValidationError(_("Password must contain at least one number"))
        if not re.search(r'[\W_]', password):
            raise ValidationError(_("Password must contain at least one special character"))