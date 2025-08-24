from django.shortcuts import render
from rest_framework import generics, status
from django.contrib.auth.models import User
from .serializers import RegisterSerializer, PasswordResetConfirmSerializer
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.core.mail import send_mail
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

# ✅ Register API
class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    permission_classes = [AllowAny]
    serializer_class = RegisterSerializer

# ✅ Password Reset Request
class PasswordResetRequestView(generics.GenericAPIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        email = request.data.get("email")
        try:
            user = User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            
            # ✅ Use frontend URL (React app)
            reset_link = f"http://localhost:3000/reset-password/{uid}/{token}"
            
            send_mail(
                "Password Reset Request",
                f"Click the link to reset your password: {reset_link}",
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )
            logger.info(f"Password reset email sent to {email}")
        except User.DoesNotExist:
            # ❌ Do not expose whether email exists
            logger.info(f"Password reset attempted for non-existent email: {email}")
            pass

        return Response(
            {"message": "If an account with this email exists, a reset link has been sent"},
            status=status.HTTP_200_OK,
        )

# ✅ Password Reset Confirm - FIXED VERSION
class PasswordResetConfirmView(generics.GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = PasswordResetConfirmSerializer

    def post(self, request, uidb64, token, *args, **kwargs):
        logger.info(f"Password reset confirm called with uidb64: {uidb64}, token: {token}")
        logger.info(f"Request data: {request.data}")
        
        try:
            # Decode the user ID
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
            logger.info(f"User found: {user.username} (ID: {user.pk}, Email: {user.email})")
        except (TypeError, ValueError, OverflowError, User.DoesNotExist) as e:
            logger.error(f"Failed to decode user ID or user not found: {e}")
            return Response(
                {"error": "Invalid user ID"}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        # ✅ Check token validity
        if not default_token_generator.check_token(user, token):
            logger.error(f"Invalid or expired token for user {user.username}")
            return Response(
                {"error": "Invalid or expired token"}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        logger.info("Token is valid, proceeding with password validation")

        # ✅ Validate new password using serializer
        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            logger.error(f"Serializer validation failed: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        try:
            # ✅ Save the new password
            old_password_hash = user.password  # Store old hash for verification
            logger.info(f"Old password hash: {old_password_hash[:20]}...")
            
            serializer.save(user=user)
            
            # ✅ Verify password was actually changed
            user.refresh_from_db()  # Reload user from database
            new_password_hash = user.password
            logger.info(f"New password hash: {new_password_hash[:20]}...")
            
            if old_password_hash == new_password_hash:
                logger.error("Password hash did not change - password reset failed!")
                return Response(
                    {"error": "Failed to update password"}, 
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            
            logger.info(f"Password successfully reset for user: {user.username}")
            return Response(
                {"message": "Password has been reset successfully"}, 
                status=status.HTTP_200_OK
            )
            
        except Exception as e:
            logger.error(f"Error during password reset: {str(e)}")
            return Response(
                {"error": "Failed to reset password"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )