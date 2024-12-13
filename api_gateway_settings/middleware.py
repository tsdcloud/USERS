from django.http import HttpResponsePermanentRedirect, JsonResponse
from django.urls import resolve, Resolver404
from django.utils.deprecation import MiddlewareMixin
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from django.contrib.auth.models import AnonymousUser
from rest_framework.exceptions import AuthenticationFailed
from rest_framework import status

class AppendSlashMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path
        # Check that the URL has no trailing slash and is not a request to a file
        if not path.endswith('/') and not path.split('/')[-1].count('.'):
            new_path = f"{path}/"
            try:
                # Check if the URL with the slash exists
                resolve(new_path)
                return HttpResponsePermanentRedirect(new_path)
            except Resolver404:
                return JsonResponse(
                    {"error": "This link does not exist. Check the URL and try again."},
                    status=404
                )

        # Continue with normal treatment if no modifications are required
        return self.get_response(request)


class JWTUserMiddleware(MiddlewareMixin):
    """
    Middleware to authenticate user using JWT from Authorization header.
    Validates the token and adds the user to the request object.
    """

    def process_request(self, request):
        # Extract the Authorization header
        auth_header = request.headers.get('Authorization', None)

        if not auth_header:
            # If no Authorization header is found, raise exception
            request.user = AnonymousUser()
            return

        # Ensure the token starts with "Bearer"
        if not auth_header.startswith('Bearer '):
            # return AuthenticationFailed("Invalid token format. Expected 'Bearer <token>'.")
            return JsonResponse(
                    {"error": "Invalid or expired token."},
                    status=status.HTTP_401_UNAUTHORIZED
                )

        # Extract the token
        token = auth_header.split(' ')[1]

        # Validate and decode the token using SimpleJWT
        jwt_authenticator = JWTAuthentication()
        try:
            validated_token = jwt_authenticator.get_validated_token(token)
            user = jwt_authenticator.get_user(validated_token)
        except (InvalidToken, TokenError):
            # return AuthenticationFailed("Invalid or expired token.")
            return JsonResponse(
                    {"error": "Invalid or expired token."},
                    status=status.HTTP_401_UNAUTHORIZED
                )

        # Add the user to the request
        request.user = user
