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
    
    Returns:
        dict: Contains validation errors or None if the password is valid.
    """
    errors = {}

    if len(password) < 8:
        errors['password'] = _("Password must be at least 8 characters long")
    
    if not re.search(r'[A-Z]', password):
        errors['password'] = _("Password must contain at least one uppercase letter")
    
    if not re.search(r'[a-z]', password):
        errors['password'] = _("Password must contain at least one lowercase letter")
    
    if not re.search(r'[0-9]', password):
        errors['password'] = _("Password must contain at least one number")
    
    if not re.search(r'[\W_]', password):
        errors['password'] = _("Password must contain at least one special character")

    # If there are errors, return them as a dictionary
    if errors:
        return errors

    return None  # Password is valid
        
def generate_random_chain(taille=10, caracteres=string.ascii_letters + string.digits):
    """
    Generates a random character string.

    :param size: Length of string to be generated (default: 10).
    :param characters: Set of characters to be used (default: letters and numbers).
    :return: A random character string.
    """
    return ''.join(random.choice(caracteres) for _ in range(taille))
