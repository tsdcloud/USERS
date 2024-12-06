from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.response import Response
from rest_framework import status
from .serializers import CustomTokenObtainPairSerializer
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from django.utils.timezone import now
from django.views import View

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
    Custom TokenObtainPairView to return tokens along with user information.
    """
    serializer_class = CustomTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)
        except Exception as e:
            return Response({"error": "Invalid username or password"}, status=status.HTTP_401_UNAUTHORIZED)
        
        # If validation is successful, update last_login
        user = serializer.user
        user.last_login = now()
        user.save(update_fields=["last_login"])

        # Return the token along with the user info
        return Response(serializer.validated_data, status=status.HTTP_200_OK)
