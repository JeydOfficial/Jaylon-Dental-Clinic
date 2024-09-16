from django.contrib import messages
from django.contrib.auth import logout, authenticate, login
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.shortcuts import render, redirect
from django.template.loader import render_to_string
from django.utils.html import strip_tags

from backend.models import *
from django.core.mail import send_mail
from django.conf import settings
from django.urls import reverse
from datetime import datetime, timedelta, date
import requests


def view_client_dashboard(request):
    # Check if the user is admin
    if request.user.is_superuser:
        return redirect('client_login')

    if request.user.is_authenticated:
        # Check previous unattended appointments
        now = timezone.localtime(timezone.now())
        unattended_appointments = Appointment.objects.filter(
            Q(date__lt=now.date()) |  # All appointments from previous days
            Q(date=now.date(), end_time__lt=now.time()),  # Today's appointments that have ended
            user=request.user,
            attended=False,
            status='Approved',
            missed_counted=False
        )

        # Mark appointments as missed and increment counter
        for unattended_appointment in unattended_appointments:
            unattended_appointment.missed_counted = True
            unattended_appointment.save()
            request.user.increment_missed_appointments()

        # Check if the user's account is restricted
        request.user.update_restriction_status()

    if request.method == 'POST':
        service_id = request.POST.get('service')

        if service_id:
            date_str = request.POST.get('date')
            time_slot = request.POST.get('time_slot')
            recaptcha_response = request.POST.get('g-recaptcha-response')

            # Verify reCAPTCHA
            verify_url = 'https://www.google.com/recaptcha/api/siteverify'
            values = {
                'secret': settings.RECAPTCHA_PRIVATE_KEY,
                'response': recaptcha_response
            }
            response = requests.post(verify_url, data=values)
            result = response.json()

            if result['success']:

                # Assuming that user_id and service_id refers to the User and Service model's primary key
                user = User.objects.get(pk=request.user.id)
                service = Service.objects.get(pk=service_id)

                # Parse the time slot
                start_time, end_time = time_slot.split(' - ')
                start_time = datetime.strptime(start_time, '%I:%M %p').time()
                end_time = datetime.strptime(end_time, '%I:%M %p').time()

                if request.user.is_restricted:
                    messages.error(request,
                                   f'Account restricted until {request.user.restriction_end_datetime.strftime("%m/%d/%Y %I:%M %p")}')
                else:
                    # Create the appointment
                    appointment = Appointment(
                        user=user,
                        service=service,
                        date=date_str,
                        start_time=start_time,
                        end_time=end_time,
                    )
                    appointment.save()
                    messages.success(request, 'Appointment added successfully.')
            else:
                messages.error(request, 'Invalid reCAPTCHA. Please try again.')

            return redirect('client_dashboard')
        else:
            name = request.POST.get('name')
            email = request.POST.get('email')
            message = request.POST.get('message')

            html_message = render_to_string('contact_form_email_template.html', {
                'name': name,
                'email': email,
                'message': message,
            })
            plain_message = strip_tags(html_message)

            subject = f"New Contact Form Submission from {name}"

            # Send email
            try:
                send_mail(
                    subject=subject,
                    message=plain_message,
                    from_email=settings.EMAIL_HOST_USER,
                    recipient_list=[settings.EMAIL_HOST_USER],
                    html_message=html_message,
                    fail_silently=False,
                )
                messages.success(request, 'Your message has been sent successfully. We will get back to you soon.')
            except Exception as e:
                messages.error(request, 'An error occurred while sending your message. Please try again later.')

    services = Service.objects.all()
    images = GalleryImage.objects.all()

    # Check if the user is authenticated before filtering appointments
    if request.user.is_authenticated:
        appointments = Appointment.objects.filter(user=request.user)
    else:
        appointments = None

    # Check if the user has seen the Privacy and Policy
    show_privacy_modal = False
    if request.user.is_authenticated and not request.user.has_agreed_privacy_policy:
        show_privacy_modal = True
        request.user.has_agreed_privacy_policy = True
        request.user.save()

    context = {
        'services': services,
        'images': images,
        'appointments': appointments,
        'recaptcha_site_key': settings.RECAPTCHA_PUBLIC_KEY,
        'show_privacy_modal': show_privacy_modal,
    }
    return render(request, 'client_dashboard.html', context)


@login_required(login_url='client_login')
def view_client_profile(request):
    # Check if the user is admin
    if request.user.is_superuser:
        return redirect('client_login')

    user = User.objects.get(id=request.user.id)

    # Fetch existing medical questionnaire or create a new one
    medical_questionnaire, created = MedicalQuestionnaire.objects.get_or_create(user=user)

    if request.method == 'POST':
        profile_id = request.POST.get('profile_id')
        if profile_id:
            new_first_name = request.POST.get('first_name')
            new_last_name = request.POST.get('last_name')
            new_phone_number = request.POST.get('phone_number')
            new_sex = request.POST.get('sex')
            new_current_address = request.POST.get('current_address')
            new_birthday = request.POST.get('birthday')
            new_age = request.POST.get('age')
            new_password = request.POST.get('password')
            confirm_new_password = request.POST.get('confirm_password')

            # Update user details
            user.first_name = new_first_name
            user.last_name = new_last_name
            user.phone_number = new_phone_number
            user.sex = new_sex
            user.current_address = new_current_address
            user.birthday = new_birthday
            user.age = new_age

            # Check if passwords are being updated
            if new_password:
                # Check if passwords match
                if new_password != confirm_new_password:
                    messages.error(request, 'Passwords do not match.')
                    return redirect('client_profile')
                user.set_password(new_password)

            user.save()
            messages.success(request, 'Your profile information have been updated successfully.')
            return redirect('client_dashboard')

        else:
            # Update medical questionnaire
            medical_questionnaire.physician_care = request.POST.get('q1') == 'Yes'
            medical_questionnaire.high_blood_pressure = request.POST.get('q2') == 'Yes'
            medical_questionnaire.heart_disease = request.POST.get('q3') == 'Yes'
            medical_questionnaire.allergic = request.POST.get('q4') == 'Yes'
            medical_questionnaire.diabetes = request.POST.get('q5') == 'Yes'
            medical_questionnaire.blood_disease = request.POST.get('q6') == 'Yes'
            medical_questionnaire.bleeder = request.POST.get('q7') == 'Yes'
            medical_questionnaire.excessive_bleeding = request.POST.get('q8') == 'Yes'
            medical_questionnaire.recent_infection = request.POST.get('q9') == 'Yes'
            medical_questionnaire.anesthetic_reactions = request.POST.get('q10') == 'Yes'
            medical_questionnaire.previous_dental_surgery = request.POST.get('q11') == 'Yes'
            medical_questionnaire.health_impression = request.POST.get('q12')

            medical_questionnaire.save()

            messages.success(request, 'Your medical information have been updated successfully.')
            return redirect('client_profile')

    # Prepare medical questions for the template
    medical_questions = [
        {'text': 'Are you under physician\'s care?', 'type': 'yes_no',
         'answer': 'Yes' if medical_questionnaire.physician_care else (
             'No' if medical_questionnaire.physician_care is not None else '')},
        {'text': 'Do you have high blood pressure?', 'type': 'yes_no',
         'answer': 'Yes' if medical_questionnaire.high_blood_pressure else (
             'No' if medical_questionnaire.high_blood_pressure is not None else '')},
        {'text': 'Do you have heart disease?', 'type': 'yes_no',
         'answer': 'Yes' if medical_questionnaire.heart_disease else (
             'No' if medical_questionnaire.heart_disease is not None else '')},
        {'text': 'Are you allergic to any drugs, medicine, foods, anesthetics?', 'type': 'yes_no',
         'answer': 'Yes' if medical_questionnaire.allergic else (
             'No' if medical_questionnaire.allergic is not None else '')},
        {'text': 'Do you have diabetes?', 'type': 'yes_no', 'answer': 'Yes' if medical_questionnaire.diabetes else (
            'No' if medical_questionnaire.diabetes is not None else '')},
        {'text': 'Do you have any blood disease?', 'type': 'yes_no',
         'answer': 'Yes' if medical_questionnaire.blood_disease else (
             'No' if medical_questionnaire.blood_disease is not None else '')},
        {'text': 'Are you a bleeder?', 'type': 'yes_no', 'answer': 'Yes' if medical_questionnaire.bleeder else (
            'No' if medical_questionnaire.bleeder is not None else '')},
        {'text': 'Have you experienced excessive bleeding after tooth extraction?', 'type': 'yes_no',
         'answer': 'Yes' if medical_questionnaire.excessive_bleeding else (
             'No' if medical_questionnaire.excessive_bleeding is not None else '')},
        {'text': 'Have you or have you recently had evidence of infection such as boils, infected wounds?',
         'type': 'yes_no', 'answer': 'Yes' if medical_questionnaire.recent_infection else (
            'No' if medical_questionnaire.recent_infection is not None else '')},
        {'text': 'Have you ever had any reactions from local anesthetics?', 'type': 'yes_no',
         'answer': 'Yes' if medical_questionnaire.anesthetic_reactions else (
             'No' if medical_questionnaire.anesthetic_reactions is not None else '')},
        {'text': 'Have you had any dental surgery before?', 'type': 'yes_no',
         'answer': 'Yes' if medical_questionnaire.previous_dental_surgery else (
             'No' if medical_questionnaire.previous_dental_surgery is not None else '')},
        {'text': 'What is your impression of your present health?', 'type': 'health_status',
         'answer': medical_questionnaire.health_impression or ''},
    ]

    context = {
        'user': request.user,
        'medical_questions': medical_questions,
    }
    return render(request, 'client_profile.html', context)


def client_login(request):
    # Check if the user is already authenticated
    if request.user.is_authenticated and not request.user.is_superuser:
        return redirect('client_dashboard')

    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        # Authenticate the user
        user = authenticate(request, email=email, password=password)

        if user is not None:
            if user.email_verified:
                login(request, user)
                return redirect('client_dashboard')
            else:
                messages.error(request, 'Please verify your email before logging in.')
        else:
            messages.error(request, 'Invalid username or password.')

    return render(request, 'client_login.html')


def client_register(request):
    # Check if the user is already authenticated
    if request.user.is_authenticated and not request.user.is_superuser:
        return redirect('client_dashboard')

    if request.method == 'POST':
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        email = request.POST.get('email')
        phone_number = request.POST.get('phone_number')
        sex = request.POST.get('sex')
        current_address = request.POST.get('current_address')
        birthday = request.POST.get('birthday')
        age = request.POST.get('age')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        # Check if passwords match
        if password != confirm_password:
            messages.error(request, 'Passwords do not match.')
            return redirect('accounts')

        # Check if the email is already taken
        if User.objects.filter(email=email).exists():
            messages.error(request, 'Email is already registered.')
            return redirect('client_register')

        # Create a new user if email is unique
        user = User(
            first_name=first_name,
            last_name=last_name,
            email=email,
            phone_number=phone_number,
            sex=sex,
            current_address=current_address,
            birthday=birthday,
            age=age,
        )
        user.set_password(password)
        user.generate_verification_token()
        user.save()

        # Send verification email
        verification_link = request.build_absolute_uri(
            reverse('client_verify_email', args=[user.verification_token])
        )

        # Render the HTML template
        html_message = render_to_string('email_verification_template.html', {
            'user': user,
            'verification_link': verification_link,
        })

        # Create a plain text version of the HTML email
        plain_message = strip_tags(html_message)

        # Send the email
        send_mail(
            subject='Verify Your Email - Jaylon Dental Clinic',
            message=plain_message,
            from_email=settings.EMAIL_HOST_USER,
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )

        messages.success(request, 'Registration successful. Please check your email to verify your account.')
        return redirect('client_login')

    return render(request, 'client_register.html')


def verify_email(request, token):
    try:
        user = User.objects.get(verification_token=token)

        # Check if the verification token has a creation time
        if user.verification_token_created:
            token_age = timezone.localtime(timezone.now()) - user.verification_token_created
            if token_age > timedelta(hours=24):
                messages.error(request, 'Verification link has expired. Please request a new one.')
                return redirect('client_register')
        else:
            # If there's no creation time, we can't verify the token age
            messages.error(request, 'Invalid verification token. Please request a new one.')
            return redirect('client_register')

        # If we get here, the token is valid
        user.email_verified = True
        user.verification_token = None
        user.verification_token_created = None
        user.save()
        messages.success(request, 'Your email has been verified. You can now log in.')
        return redirect('client_login')
    except User.DoesNotExist:
        messages.error(request, 'Invalid verification token.')
        return redirect('client_login')


def client_forgot_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            user = User.objects.get(email=email, is_superuser=False)
            # Generate a random token
            token = get_random_string(length=32)
            user.password_reset_token = token
            user.password_reset_token_created = datetime.now()
            user.save()

            # Send password reset email
            reset_link = request.build_absolute_uri(
                reverse('client_reset_password', args=[token])
            )

            html_message = render_to_string('password_reset_email_template.html', {
                'user': user,
                'reset_link': reset_link,
            })
            plain_message = strip_tags(html_message)

            send_mail(
                subject='Reset Your Password - Jaylon Dental Clinic',
                message=plain_message,
                from_email=settings.EMAIL_HOST_USER,
                recipient_list=[user.email],
                html_message=html_message,
                fail_silently=False,
            )

            messages.success(request, 'Password reset instructions have been sent to your email.')
            return redirect('client_login')
        except User.DoesNotExist:
            messages.error(request, 'No user with that email address exists.')

    return render(request, 'client_forgot_password.html')


def client_reset_password(request, token):
    try:
        user = User.objects.get(password_reset_token=token, is_superuser=False)
        if request.method == 'POST':
            new_password = request.POST.get('new_password')
            confirm_password = request.POST.get('confirm_password')

            if new_password == confirm_password:
                user.set_password(new_password)
                user.password_reset_token = None
                user.password_reset_token_created = None
                user.save()
                messages.success(request,
                                 'Your password has been reset successfully. You can now log in.')
                return redirect('client_login')
            else:
                messages.error(request, 'Passwords do not match.')
        return render(request, 'client_reset_password.html')
    except User.DoesNotExist:
        messages.error(request, 'Invalid password reset token.')
        return redirect('client_login')


@login_required(login_url='client_login')
def client_logout(request):
    logout(request)
    return redirect('client_dashboard')
