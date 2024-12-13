from django.core.exceptions import ValidationError
import re
from django.utils.translation import gettext_lazy as _
import random
import string



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
        
def generate_random_chain(taille=10, caracteres=string.ascii_letters + string.digits):
    """
    Generates a random character string.

    :param size: Length of string to be generated (default: 10).
    :param characters: Set of characters to be used (default: letters and numbers).
    :return: A random character string.
    """
    return ''.join(random.choice(caracteres) for _ in range(taille))
