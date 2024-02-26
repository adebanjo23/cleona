from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.views import TokenObtainPairView

User = get_user_model()

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    username_field = User.EMAIL_FIELD

    def validate(self, attrs):
        # Ensure we use 'email' instead of 'username'
        attrs[self.username_field] = attrs.get(self.username_field) or attrs.get('email')
        return super(CustomTokenObtainPairSerializer, self).validate(attrs)

class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer


