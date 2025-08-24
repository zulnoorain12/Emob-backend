from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
import logging

logger = logging.getLogger(__name__)

# ✅ For Signup
class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True, required=True, validators=[validate_password]
    )
    password2 = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ('username', 'email', 'password', 'password2')

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Passwords do not match"})
        return attrs

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password']
        )
        return user

# ✅ For Password Reset Confirm - FIXED VERSION
class PasswordResetConfirmSerializer(serializers.Serializer):
    new_password = serializers.CharField(
        write_only=True, required=True, validators=[validate_password]
    )
    confirm_password = serializers.CharField(write_only=True, required=True)

    def validate(self, attrs):
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError(
                {"password": "New password and confirm password do not match"}
            )
        return attrs

    def save(self, user):
        """
        Save the new password to the user
        """
        password = self.validated_data['new_password']
        logger.info(f"Setting new password for user: {user.username}")
        logger.info(f"Password length: {len(password)}")
        
        # ✅ Use set_password to properly hash and save the password
        user.set_password(password)
        user.save()
        
        logger.info(f"Password saved successfully for user: {user.username}")
        return user