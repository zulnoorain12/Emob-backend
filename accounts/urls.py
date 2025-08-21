from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .views import RegisterView, PasswordResetRequestView, PasswordResetConfirmView

urlpatterns = [
    # ✅ User Auth
    path("signup/", RegisterView.as_view(), name="signup"),
    path("login/", TokenObtainPairView.as_view(), name="login"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),

    # ✅ Forgot/Reset Password
    path("password_reset/", PasswordResetRequestView.as_view(), name="password_reset"),
    path("password_reset_confirm/<uidb64>/<token>/", PasswordResetConfirmView.as_view(), name="password_reset_confirm"),
]
