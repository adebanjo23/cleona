from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
import random


class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        """
        Creates and saves a User with the given email and password.
        """
        if not email:
            raise ValueError('Users must have an email address')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """
        Creates and saves a superuser (admin) with the given email and password.
        Note: Renaming this to create_superuser for clarity, but it creates an admin.
        """
        extra_fields.setdefault('is_admin', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('is_verified', True)
        extra_fields.setdefault('is_staff', True)  # Ensure superusers are also staff

        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser):
    email = models.EmailField(_('email address'), max_length=255, unique=True)
    is_admin = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=True)  # Added is_staff field with default True
    date_joined = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []  # You can specify other fields that are required on user creation here

    objects = UserManager()

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        # Admin users have all permissions
        return self.is_admin

    def has_module_perms(self, app_label):
        # Admin users have permissions to view all apps
        return self.is_admin


class OTP(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp_code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    is_verified = models.BooleanField(default=False)

    objects = models.Manager()

    def __str__(self):
        # noinspection PyUnresolvedReferences
        return f"OTP for {self.user.email}"

    @staticmethod
    def generate_otp_code(length=6):
        numbers = '0123456789'
        return ''.join(random.choice(numbers) for i in range(length))

    def save(self, *args, **kwargs):
        if not self.otp_code:
            self.otp_code = self.generate_otp_code()
        super().save(*args, **kwargs)

    @property
    def is_expired(self):
        # Assuming OTP is valid for 10 minutes
        return timezone.now() - self.created_at > timezone.timedelta(minutes=10)


class PasswordResetToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=100, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        return timezone.now() - self.created_at > timezone.timedelta(hours=24)
