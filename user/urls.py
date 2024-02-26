from django.urls import path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

from . import views


urlpatterns = [
    path('register/', views.register, name='register'),
    path('delete_user/', views.delete_user, name='delete_user'),
    path('resend_otp/', views.resend_otp, name='resend_otp'),
    path('verify_otp/', views.verify_otp, name='verify_otp'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('list_staffs/', views.list_staffs, name='list_staffs'),
    path('login/', views.login, name='login'),
    path('logout/', views.logout, name='logout'),
    path('test_token/', views.test_token, name='test_token'),
    path('admin_login/', views.admin_login, name='admin_login'),
    path('forgot_password/', views.forgot_password, name='forgot_password'),
    path('reset_password/', views.reset_password, name='reset_password'),
    path('change_password/', views.change_password, name='change_password'),
]
