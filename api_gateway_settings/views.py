from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.response import Response
from rest_framework import status
# from .serializers import CustomTokenObtainPairSerializer
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from django.utils.timezone import now
from django.contrib.auth import authenticate
from api_users.models import CustomUser

class UserInfoView(APIView):
    """
    View to retrieve user information from the token.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response({
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name
        })

class CustomTokenObtainPairView(TokenObtainPairView):
    """
    Custom TokenObtainPairView to support login with email or username and 
    return tokens along with user information and handle login verification.
    """

    def post(self, request, *args, **kwargs):
        username_or_email = request.data.get('login')
        password = request.data.get('password')

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

        # Authenticate user
        user = authenticate(username=username, password=password)

        if not user:
            return Response(
                {"success": False, "message": "Invalid email/username or password."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        # Generate tokens
        serializer = self.get_serializer(data={"username": username, "password": password})
        serializer.is_valid(raise_exception=True)

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