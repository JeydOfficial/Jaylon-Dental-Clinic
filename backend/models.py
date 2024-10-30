from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.models import BaseUserManager
from django.utils.crypto import get_random_string
from django.utils import timezone


class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        """
        Create and return a regular user with an email and password.
        """
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """
        Create and return a superuser with an email and password.
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, password, **extra_fields)


class User(AbstractUser):
    username = None  # Remove the username field
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=15, blank=True)
    sex = models.CharField(max_length=6, choices=[('Male', 'Male'), ('Female', 'Female')])
    current_address = models.TextField(blank=True)
    birthday = models.DateField(null=True, blank=True)
    age = models.PositiveIntegerField(null=True, blank=True)
    email_verified = models.BooleanField(default=False)
    verification_token = models.CharField(max_length=100, blank=True, null=True)
    verification_token_created = models.DateTimeField(blank=True, null=True)
    password_reset_token = models.CharField(max_length=100, blank=True, null=True)
    password_reset_token_created = models.DateTimeField(blank=True, null=True)
    consecutive_missed_appointments = models.IntegerField(default=0)
    is_restricted = models.BooleanField(default=False)
    restriction_end_time = models.DateTimeField(null=True, blank=True)
    has_agreed_privacy_policy = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = CustomUserManager()  # Use the custom manager

    def generate_verification_token(self):
        self.verification_token = get_random_string(length=32)
        self.verification_token_created = timezone.localtime(timezone.now())
        self.save()

    def generate_password_reset_token(self):
        self.password_reset_token = get_random_string(length=32)
        self.password_reset_token_created = timezone.localtime(timezone.now())
        self.save()

    def update_restriction_status(self):
        now = timezone.localtime(timezone.now())
        if self.is_restricted and self.restriction_end_time and now >= self.restriction_end_time:
            self.is_restricted = False
            self.restriction_end_time = None
            self.consecutive_missed_appointments = 0
            self.save()

    def increment_missed_appointments(self):
        now = timezone.localtime(timezone.now())
        self.consecutive_missed_appointments += 1
        if self.consecutive_missed_appointments == 3:
            self.is_restricted = True
            self.restriction_end_time = now + timezone.timedelta(hours=12)
        elif self.consecutive_missed_appointments == 5:
            self.is_restricted = True
            self.restriction_end_time = now + timezone.timedelta(hours=24)
        self.save()

        # elif self.consecutive_missed_appointments == 5:
        #       self.is_restricted = True
        #       self.restriction_end_time = now + timezone.timedelta(hours=24)

    def reset_missed_appointments(self):
        self.consecutive_missed_appointments = 0
        self.save()

    def __str__(self):
        return f'{self.first_name} {self.last_name}'


class GalleryImage(models.Model):
    image = models.ImageField(upload_to='gallery/')
    uploaded_at = models.DateTimeField(auto_now_add=True)


class Service(models.Model):
    title = models.CharField(max_length=255)
    description = models.TextField()
    duration = models.PositiveIntegerField()  # Duration in minutes
    image = models.ImageField(upload_to='services/')  # Path where images will be stored

    def __str__(self):
        return self.title


class Appointment(models.Model):
    STATUS_CHOICES = [
        ('Pending', 'Pending'),
        ('Approved', 'Approved'),
        ('Cancelled', 'Cancelled'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    service = models.ForeignKey(Service, on_delete=models.CASCADE)
    date = models.DateField()
    start_time = models.TimeField()
    end_time = models.TimeField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Pending')
    attended = models.BooleanField(default=False)
    reminder_sent = models.BooleanField(default=False)
    missed_counted = models.BooleanField(default=False)

    class Meta:
        indexes = [
            models.Index(fields=['date', 'start_time', 'status', 'reminder_sent']),
        ]

    def __str__(self):
        return f"{self.user.first_name} {self.user.last_name} - {self.service.title} on {self.date} at {self.start_time}"


class MedicalQuestionnaire(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    physician_care = models.BooleanField(null=True, blank=True)
    high_blood_pressure = models.BooleanField(null=True, blank=True)
    heart_disease = models.BooleanField(null=True, blank=True)
    allergic = models.BooleanField(null=True, blank=True)
    diabetes = models.BooleanField(null=True, blank=True)
    blood_disease = models.BooleanField(null=True, blank=True)
    bleeder = models.BooleanField(null=True, blank=True)
    excessive_bleeding = models.BooleanField(null=True, blank=True)
    recent_infection = models.BooleanField(null=True, blank=True)
    anesthetic_reactions = models.BooleanField(null=True, blank=True)
    previous_dental_surgery = models.BooleanField(null=True, blank=True)
    health_impression = models.CharField(max_length=5, choices=[('Good', 'Good'), ('Fair', 'Fair'), ('Poor', 'Poor')],
                                         null=True, blank=True)

    def __str__(self):
        return f"Medical Questionnaire for {self.first_name} {self.last_name}"
