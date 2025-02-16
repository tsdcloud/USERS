from django.http import HttpResponsePermanentRedirect, JsonResponse
from django.urls import resolve, Resolver404
from django.utils.deprecation import MiddlewareMixin
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from django.contrib.auth.models import AnonymousUser
from rest_framework import status
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
import jwt
from . import settings

from api_users.models import UserTokenBlacklisted

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
    Middleware to support both session-based and JWT authentication.
    """

    def process_request(self, request):
        # Skip if user is already authenticated via session
        if hasattr(request, 'user') and request.user.is_authenticated:
            return

        # Extract the Authorization header
        auth_header = request.headers.get('Authorization', None)

        if not auth_header:
            request.user = AnonymousUser()
            return
            # return JsonResponse(
            #     {"success": False, "error": "Authentication credentials were not provided."},
            #     status=status.HTTP_401_UNAUTHORIZED
            # )

        if not auth_header.startswith('Bearer '):
            return JsonResponse(
                {"success": False, "error": "Invalid token format. Expected 'Bearer <token>'."},
                status=status.HTTP_401_UNAUTHORIZED
            )

        # Extract the JWT token
        token = auth_header.split(' ')[1]

        # Validate and decode the token using SimpleJWT
        jwt_authenticator = JWTAuthentication()

        try:
            # Decode the token
            validated_token = jwt_authenticator.get_validated_token(token)

            try:
                user_token_blacklisted = UserTokenBlacklisted.objects.get(access_token=validated_token)
                # decode user refresh token
                if user_token_blacklisted :
                    decoded_payload = jwt.decode(
                        user_token_blacklisted.refresh_token,
                        settings.SIMPLE_JWT["SIGNING_KEY"],
                        algorithms=[settings.SIMPLE_JWT["ALGORITHM"]],
                        # options={"verify_exp": True},
                    )
                    # RefreshToken(user_token_blacklisted.refresh_token)
                    jti = decoded_payload.get('jti')  

                    # print(jti)

                    # Get OutstandingToken instance
                    outstanding_token = OutstandingToken.objects.filter(jti=jti).first()
                    if not outstanding_token:
                        return JsonResponse(
                            {"success": False, "error": "Token does not exist in the database."},
                            status=status.HTTP_401_UNAUTHORIZED
                        )

                    # Check if the token is blacklisted
                    if BlacklistedToken.objects.filter(token=outstanding_token).exists():
                        return JsonResponse(
                            # {"error": "Token provided is blacklisted."},
                            {"success": False, "error": "your token has been blacklisted due to a new connection, continue where you were last connected, if this is not you, contact your administrator"},
                            status=status.HTTP_401_UNAUTHORIZED
                        )
            except UserTokenBlacklisted.DoesNotExist:
                pass

            # print(validated_token)
            # print(user_refresh_token.refresh_token)

            # Retrieve the user from the token
            user = jwt_authenticator.get_user(validated_token)

        except (InvalidToken, TokenError):
            return JsonResponse(
                {"success": False, "error": "Invalid or expired token."},
                status=status.HTTP_401_UNAUTHORIZED
            )

        # Attach the authenticated user to the request
        request.user = user
