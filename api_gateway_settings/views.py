from rest_framework_simplejwt.views import TokenObtainPairView, TokenBlacklistView, TokenVerifyView
from rest_framework.response import Response
from rest_framework import status
# from .serializers import CustomTokenObtainPairSerializer
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from django.utils.timezone import now
from django.contrib.auth import authenticate
from api_users.models import CustomUser, UserToken, UserTokenBlacklisted
from rest_framework_simplejwt.tokens import RefreshToken
import jwt
from rest_framework_simplejwt.authentication import JWTAuthentication


class UserInfoView(APIView):
    """
    View to retrieve user information from the token.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response({"success": True, "data":{
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "is_admin": user.is_admin,
            "is_superuser": user.is_superuser,
            "is_staff": user.is_staff
        }})

class CustomTokenObtainPairView(TokenObtainPairView):
    """
    Custom TokenObtainPairView to support login with email or username and 
    return tokens along with user information and handle login verification.
    """

    def post(self, request, *args, **kwargs):
        username_or_email = request.data.get('login')
        password = request.data.get('password')

        if not username_or_email or not password:
            return Response({"success": False, "error": "username_or_email and password are required."}, status=status.HTTP_400_BAD_REQUEST)

        # Determine if identifier is email or username
        if '@' in username_or_email:
            # Treat as email
            try:
                username = CustomUser.objects.get(email=username_or_email).username
            except CustomUser.DoesNotExist:
                return Response(
                    {"success": False, "message": "Invalid email or username."},
                    status=status.HTTP_401_UNAUTHORIZED,
                )
        else:
            # Treat as username
            username = username_or_email

        # check if the user is active
        try:
            if '@' in username_or_email :
                user = CustomUser.objects.filter(email=username_or_email).first()
            else:
                user = CustomUser.objects.filter(username=username_or_email).first()

            if user:
                if not user.is_active:
                    return Response(
                        {"message": "Account deactivated, please contact administrator."},
                        status=status.HTTP_401_UNAUTHORIZED,
                    )
        except CustomUser.DoesNotExist:
            pass
        
        # Authenticate user
        user = authenticate(username=username, password=password)

        if not user:
            return Response(
                {"success": False, "message": "Invalid email/username or password."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        # Check if a token exists and is valid
        try:
            user_token = UserToken.objects.get(user=user)
            if user_token.is_valid():
                # blacklist existing tokens
                refresh = RefreshToken(user_token.refresh_token)
                refresh.blacklist()

                UserTokenBlacklisted.objects.create(user=user, refresh_token=str(user_token.refresh_token), access_token=str(user_token.access_token))

                user_token.delete()
            else:
                user_token.delete() 
        except UserToken.DoesNotExist:
            pass

        # Generate tokens
        serializer = self.get_serializer(data={"username": username, "password": password})
        serializer.is_valid(raise_exception=True)

        refresh = serializer.validated_data["refresh"]
        access = serializer.validated_data["access"]
        
        UserToken.objects.create(user=user, refresh_token=str(refresh), access_token=str(access))

        # Update last login
        user.last_login = now()
        user.save(update_fields=["last_login"])

        # Return tokens and user info
        return Response(
            {
                "success": True,
                "message": "Authentication successful.",
                "data": serializer.validated_data,
            },
            status=status.HTTP_200_OK,
        )

class CustomTokenVerifyView(TokenVerifyView):

    def post(self, request, *args, **kwargs):
        """
        This method can be used to verify the JWT token. Only admin and super users can access it.
        """
        jwt_authenticator = JWTAuthentication()
        
        auth_header = request.headers.get('Authorization', None)

        if not auth_header:
            return Response({"success": False, "error": "Authentication credentials were not provided."}, status=status.HTTP_401_UNAUTHORIZED)


        # Extract the JWT token
        token = auth_header.split(' ')[1]

        # Decode the token
        validated_token = jwt_authenticator.get_validated_token(token)

        # Retrieve the user from the token
        user = jwt_authenticator.get_user(validated_token)

        print(user.is_superuser)

        if not (user.is_superuser or user.is_admin):
            return Response({"success": False, "error": "Only admin or super admin can perform this action."}, status=status.HTTP_403_FORBIDDEN)

        return super().post(request, *args, **kwargs)


class CustomTokenBlacklistView(TokenBlacklistView):

    def post(self, request, *args, **kwargs):
        """
        This method can be used to blacklist the JWT token. Only admin and super users can access it.
        """
        jwt_authenticator = JWTAuthentication()
        
        auth_header = request.headers.get('Authorization', None)

        if not auth_header:
            return Response({"success": False, "error": "Authentication credentials were not provided."}, status=status.HTTP_401_UNAUTHORIZED)

        # Extract the JWT token
        token = auth_header.split(' ')[1]

        # Decode the token
        validated_token = jwt_authenticator.get_validated_token(token)

        # Retrieve the user from the token
        user = jwt_authenticator.get_user(validated_token)

        print(user.is_superuser)

        if not (user.is_superuser or user.is_admin):
            return Response({"success": False, "error": "Only admin or super admin can perform this action."}, status=status.HTTP_403_FORBIDDEN)

        return super().post(request, *args, **kwargs)
