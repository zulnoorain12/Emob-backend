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


# ✅ Register API
class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    permission_classes = [AllowAny]
    serializer_class = RegisterSerializer


# ✅ Password Reset Request
class PasswordResetRequestView(generics.GenericAPIView):
    permission_classes = [AllowAny]   # 👈 FIXED

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
        except User.DoesNotExist:
            # ❌ Do not expose whether email exists
            pass

        return Response(
            {"message": "If an account with this email exists, a reset link has been sent"},
            status=status.HTTP_200_OK,
        )


# ✅ Password Reset Confirm
class PasswordResetConfirmView(generics.GenericAPIView):
    permission_classes = [AllowAny]   # 👈 FIXED
    serializer_class = PasswordResetConfirmSerializer

    def post(self, request, uidb64, token, *args, **kwargs):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({"error": "Invalid user ID"}, status=status.HTTP_400_BAD_REQUEST)

        # ✅ Check token validity
        if not default_token_generator.check_token(user, token):
            return Response({"error": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)

        # ✅ Validate new password
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(user=user)

        return Response({"message": "Password has been reset successfully"}, status=status.HTTP_200_OK)
