from django.core.management.base import BaseCommand

from user.models import User


class Command(BaseCommand):
    help = 'Creates an admin user'

    def add_arguments(self, parser):
        parser.add_argument('email', type=str, help='The email for the admin user')
        parser.add_argument('password', type=str, help='The password for the admin user')

    def handle(self, *args, **options):
        email = options['email']
        password = options['password']

        if not User.objects.filter(email=email).exists():
            User.objects.create_superuser(email=email, password=password)
            self.stdout.write(self.style.SUCCESS(f'Admin user with email {email} was created successfully!'))
        else:
            self.stdout.write(self.style.ERROR('User with this email already exists.'))
