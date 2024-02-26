from django.core.exceptions import ObjectDoesNotExist
from django.core.mail import send_mail, EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.utils import timezone
from .models import User, OTP, PasswordResetToken
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework import status
import uuid


@api_view(['POST'])
def register(request):
    email = request.data.get("email")
    password = request.data.get("password")

    if not email or not password:
        return Response("All fields are required", status=status.HTTP_400_BAD_REQUEST)

    # Check if user already exists
    if User.objects.filter(email=email).exists():
        return Response("Email is already in use", status=status.HTTP_400_BAD_REQUEST)

    # Create new user
    user = User.objects.create_user(email=email, password=password)

    # Generate OTP and attempt to send it
    otp_code = OTP.generate_otp_code()
    otp_entry = OTP.objects.create(user=user, otp_code=otp_code)

    try:
        my_subject = 'OTP Verification Email'
        my_recipient = email
        html_content = render_to_string("index.html", {'otp_code': otp_entry.otp_code})
        plain_message = strip_tags(html_content)

        # Send email
        send_mail(
            subject=my_subject,
            message=plain_message,
            from_email=None,
            recipient_list=[my_recipient],
            html_message=html_content,
            fail_silently=False,
        )
    except Exception as e:
        # Log the error or handle it as needed
        # Even if OTP sending fails, the user is informed of successful account creation
        print(f"Failed to send OTP email to {email}: {e}")  # Consider using logging instead of print in production

    return Response(
        "User registered successfully. Please check your email for the OTP. If you didn't receive an OTP, contact support.",
        status=status.HTTP_201_CREATED)


@api_view(['POST'])
def resend_otp(request):
    email = request.data.get('email')
    if not email:
        return Response({"error": "Email address is required."}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = User.objects.get(email=email)
    except ObjectDoesNotExist:
        return Response({"error": "User does not exist."}, status=status.HTTP_404_NOT_FOUND)

    new_otp_code = OTP.generate_otp_code()
    OTP.objects.update_or_create(
        user=user,
        defaults={'otp_code': new_otp_code, 'created_at': timezone.now(), 'is_verified': False}
    )

    try:
        my_subject = 'OTP Verification Email'
        my_recipient = email
        html_content = render_to_string("index.html", {'otp_code': new_otp_code})
        plain_message = strip_tags(html_content)

        # Send email
        send_mail(
            subject=my_subject,
            message=plain_message,
            from_email=None,
            recipient_list=[my_recipient],
            html_message=html_content,
            fail_silently=False,
        )
        return Response({"message": "OTP resent successfully. Please check your email."}, status=status.HTTP_200_OK)

    except Exception as e:
        print(f"Failed to send OTP email to {email}: {e}")
        # Log the error or handle it as needed
        return Response({"error": "Failed to send OTP. Please try again later."},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
def verify_otp(request):
    email = request.data.get('email')
    input_otp = request.data.get('otp')

    if not email or not input_otp:
        return Response({"error": "Email and OTP code are required."}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = User.objects.get(email=email)
    except ObjectDoesNotExist:
        return Response({"error": "User does not exist."}, status=status.HTTP_404_NOT_FOUND)

    try:
        otp_entry = OTP.objects.get(user=user, is_verified=False)
        if otp_entry.is_expired:
            return Response({"error": "OTP has expired. Please request a new one."}, status=status.HTTP_400_BAD_REQUEST)
        elif otp_entry.otp_code == input_otp:
            otp_entry.is_verified = True
            otp_entry.save()
            user.is_verified = True
            user.save()
            return Response({"message": "OTP verified successfully. User is now verified."}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Incorrect OTP."}, status=status.HTTP_400_BAD_REQUEST)
    except ObjectDoesNotExist:
        return Response({"error": "OTP not found or already verified."}, status=status.HTTP_404_NOT_FOUND)


@api_view(['POST'])
def login(request):
    email = request.data.get('email')
    password = request.data.get('password')

    user = User.objects.filter(email=email).first()

    if user is None:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

    if not user.check_password(password):
        return Response({'error': 'Incorrect Password'}, status=status.HTTP_401_UNAUTHORIZED)

    refresh = RefreshToken.for_user(user)
    # noinspection PyUnresolvedReferences
    return Response({
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }, status=status.HTTP_200_OK)


@api_view(['POST'])
def admin_login(request):
    email = request.data.get('email')
    password = request.data.get('password')

    # Attempt to retrieve the user with the given email
    user = User.objects.filter(email=email).first()

    # Check if user exists
    if user is None:
        return Response({'error': 'Admin not found'}, status=status.HTTP_404_NOT_FOUND)

    # Check if password is correct
    if not user.check_password(password):
        return Response({'error': 'Incorrect Password'}, status=status.HTTP_401_UNAUTHORIZED)

    # Check if user is an admin
    if not user.is_admin:
        return Response({'error': 'Unauthorized Access'}, status=status.HTTP_403_FORBIDDEN)

    # Generate JWT tokens for the admin
    refresh = RefreshToken.for_user(user)
    # noinspection PyUnresolvedReferences
    return Response({
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def test_token(request):
    return Response("passed!")


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_staffs(request):
    if request.method == 'GET':
        if request.user.is_admin:
            staff_members = User.objects.filter(is_staff=True, is_admin=False)
            serialized_data = []
            for staff_member in staff_members:
                serialized_data.append({
                    'email': staff_member.email,
                    'date_joined': staff_member.date_joined
                })
            return Response(serialized_data, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Unauthorized Access'}, status=status.HTTP_403_FORBIDDEN)


@api_view(['POST'])
@permission_classes([IsAuthenticated, IsAdminUser])  # Ensure the user is authenticated and is an admin
def delete_user(request):
    email = request.data.get('email')
    if not email:
        return Response({'error': 'Email address is required.'}, status=400)

    if request.user.is_admin:
        try:
            user = User.objects.get(email=email)
            user.delete()
            return Response({'message': 'User deleted successfully.'}, status=204)
        except ObjectDoesNotExist:
            return Response({'error': 'User not found.'}, status=404)
    else:
        return Response({'error': 'Unauthorized Access'}, status=status.HTTP_403_FORBIDDEN)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout(request):
    try:
        # Extract the refresh token from the request
        refresh_token = request.data.get('refresh')
        token = RefreshToken(refresh_token)

        # Attempt to blacklist the given token
        token.blacklist()

        return Response({"message": "Logged out successfully"}, status=status.HTTP_205_RESET_CONTENT)
    except Exception as e:
        return Response({"error": "Logout failed or user already logged out"}, status=status.HTTP_400_BAD_REQUEST)


def generate_unique_token():
    return str(uuid.uuid4())


@api_view(['POST'])
def forgot_password(request):
    email = request.data.get('email')
    if not email:
        return Response({"error": "Email address is required."}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        # Even if the user isn't found, don't reveal that to the requester
        return Response({"message": "If your account exists, a password reset link has been sent to your email."},
                        status=status.HTTP_200_OK)

    # Generate a unique token and save it
    token = generate_unique_token()
    PasswordResetToken.objects.create(user=user, token=token)

    # Construct the password reset link. You'll need to adjust the domain to match your frontend.
    reset_link = f"https://yourfrontenddomain.com/reset-password?token={token}"

    try:
        my_subject = 'OTP Verification Email'
        my_recipient = email
        html_content = render_to_string("forgot_password.html", {'reset_link': reset_link})
        plain_message = strip_tags(html_content)

        # Send email
        send_mail(
            subject=my_subject,
            message=plain_message,
            from_email=None,
            recipient_list=[my_recipient],
            html_message=html_content,
            fail_silently=False,
        )
    except Exception as e:
        # Handle email sending failure
        return Response({"error": "Failed to send password reset email. Please try again later."},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    return Response({"message": "If your account exists, a password reset link has been sent to your email."},
                    status=status.HTTP_200_OK)


@api_view(['POST'])
def reset_password(request):
    token = request.data.get('token')
    new_password = request.data.get('password')
    if not token or not new_password:
        return Response({"error": "Token and new password are required."}, status=status.HTTP_400_BAD_REQUEST)

    try:
        reset_token = PasswordResetToken.objects.get(token=token, user__is_active=True)
        if reset_token.is_expired():
            return Response({"error": "Token is expired."}, status=status.HTTP_400_BAD_REQUEST)
    except PasswordResetToken.DoesNotExist:
        return Response({"error": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST)

    user = reset_token.user
    user.set_password(new_password)
    user.save()

    # Optionally, delete the token after successful password reset to prevent reuse
    reset_token.delete()

    return Response({"message": "Password has been reset successfully."}, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_password(request):
    user = request.user
    old_password = request.data.get('old_password')
    new_password = request.data.get('new_password')

    if not old_password or not new_password:
        return Response({"error": "Both old and new password are required."}, status=status.HTTP_400_BAD_REQUEST)

    # Authenticate the user with the old password
    if not user.check_password(old_password):
        return Response({"error": "Old password is incorrect."}, status=status.HTTP_400_BAD_REQUEST)

    # Set the new password
    user.set_password(new_password)
    user.save()

    return Response({"message": "Password changed successfully."}, status=status.HTTP_200_OK)
