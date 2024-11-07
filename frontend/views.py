from urllib.parse import urlencode

from django.contrib import messages
from django.contrib.auth import logout, authenticate, login
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.views.decorators.http import require_POST

from backend.models import *
from django.core.mail import send_mail
from django.conf import settings
from django.urls import reverse
from datetime import datetime, timedelta, date

import requests
import json
import re


@login_required
@require_POST
def save_privacy_agreement(request):
    try:
        data = json.loads(request.body)
        request.user.has_agreed_privacy_policy = data.get('agreed', False)
        request.user.save()
        return JsonResponse({'success': True})
    except:
        return JsonResponse({'success': False})


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
                start_time = timezone.datetime.strptime(start_time, '%I:%M %p').time()
                end_time = timezone.datetime.strptime(end_time, '%I:%M %p').time()

                if request.user.is_restricted:
                    # Convert the restriction_end_time to the current time zone
                    localized_end_time = timezone.localtime(request.user.restriction_end_time)
                    formatted_end_time = localized_end_time.strftime("%B %d, %Y at %I:%M %p")
                    messages.error(request, f'Account restricted until {formatted_end_time}')
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

    # medical_questions = [
    #     {'text': 'Are you under physician\'s care?', 'type': 'yes_no'},
    #     {'text': 'Do you have high blood pressure?', 'type': 'yes_no'},
    #     {'text': 'Do you have heart disease?', 'type': 'yes_no'},
    #     {'text': 'Are you allergic to any drugs, medicine, foods, anesthetics?', 'type': 'yes_no'},
    #     {'text': 'Do you have diabetes?', 'type': 'yes_no'},
    #     {'text': 'Do you have any blood disease?', 'type': 'yes_no'},
    #     {'text': 'Are you a bleeder?', 'type': 'yes_no'},
    #     {'text': 'Have you experienced excessive bleeding after tooth extraction?', 'type': 'yes_no'},
    #     {'text': 'Have you or have you recently had evidence of infection such as boils, infected wounds?',
    #      'type': 'yes_no'},
    #     {'text': 'Have you ever had any reactions from local anesthetics?', 'type': 'yes_no'},
    #     {'text': 'Have you had any dental surgery before?', 'type': 'yes_no'},
    #     {'text': 'What is your impression of your present health?', 'type': 'health_status'},
    # ]

    services = Service.objects.all()
    images = GalleryImage.objects.all()

    for service in services:
        service.details = '\n'.join([line for line in service.details.split('\n') if line.strip()])

    # Check if the user is authenticated before filtering appointments
    if request.user.is_authenticated:
        appointments = Appointment.objects.filter(user=request.user)
    else:
        appointments = None

    # Check if the user has agreed to the privacy policy
    show_privacy_modal = False
    if request.user.is_authenticated and not request.user.has_agreed_privacy_policy:
        show_privacy_modal = True

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
            return redirect('client_profile')

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


# @login_required(login_url='client_login')
# def update_medical_questionnaire(request):
#     user = request.user
#     medical_questionnaire, created = MedicalQuestionnaire.objects.get_or_create(user=user)
#
#     try:
#         medical_questionnaire.physician_care = request.POST.get('q1') == 'Yes'
#         medical_questionnaire.high_blood_pressure = request.POST.get('q2') == 'Yes'
#         medical_questionnaire.heart_disease = request.POST.get('q3') == 'Yes'
#         medical_questionnaire.allergic = request.POST.get('q4') == 'Yes'
#         medical_questionnaire.diabetes = request.POST.get('q5') == 'Yes'
#         medical_questionnaire.blood_disease = request.POST.get('q6') == 'Yes'
#         medical_questionnaire.bleeder = request.POST.get('q7') == 'Yes'
#         medical_questionnaire.excessive_bleeding = request.POST.get('q8') == 'Yes'
#         medical_questionnaire.recent_infection = request.POST.get('q9') == 'Yes'
#         medical_questionnaire.anesthetic_reactions = request.POST.get('q10') == 'Yes'
#         medical_questionnaire.previous_dental_surgery = request.POST.get('q11') == 'Yes'
#         medical_questionnaire.health_impression = request.POST.get('q12')
#
#         medical_questionnaire.save()
#         messages.success(request, 'Thank you for completing the medical questionnaire!')
#         return JsonResponse({'success': True})
#     except Exception as e:
#         messages.error(request, 'There was an error submitting the questionnaire. Please try again.')
#         return JsonResponse({'success': False})


def client_login(request):
    # Check if the user is already authenticated
    if request.user.is_authenticated and not request.user.is_superuser:
        return redirect('client_dashboard')

    if request.method == 'POST':
        email_or_phone = request.POST.get('email_or_phone')
        password = request.POST.get('password')

        try:
            if '@' in email_or_phone:
                user = User.objects.get(email=email_or_phone)
                if not user.email_verified:
                    messages.error(request, 'Please verify your email first.')
                    return render(request, 'client_login.html')

            else:
                user = User.objects.get(phone_number=email_or_phone)
                if not user.phone_verified:
                    messages.error(request, 'Please verify your phone number first.')
                    return render(request, 'client_login.html')

            # Try to authenticate with the stored identifier
            authenticated_user = authenticate(request, username=user.identifier, password=password)

            if authenticated_user is not None:
                login(request, authenticated_user)
                return redirect('client_dashboard')
            else:
                messages.error(request, 'Invalid credentials.')
        except User.DoesNotExist:
            messages.error(request, 'User not found.')

    return render(request, 'client_login.html')


# def validate_password(password):
#     errors = []
#     if len(password) < 8:
#         errors.append("Password must be at least 8 characters long.")
#     if not re.search(r'[A-Z]', password):
#         errors.append("Password must contain at least one uppercase letter.")
#     if not re.search(r'[a-z]', password):
#         errors.append("Password must contain at least one lowercase letter.")
#     if not re.search(r'\d', password):
#         errors.append("Password must contain at least one number.")
#     if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
#         errors.append("Password must contain at least one special character.")
#     return errors


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

        # Validate required fields first
        if not (email or phone_number):
            messages.error(request, 'Either email or phone number is required.')
            return render(request, 'client_register.html', {'post_data': request.POST})

        # Check if passwords match
        if password != confirm_password:
            messages.error(request, 'Passwords do not match.')
            return render(request, 'client_register.html', {'post_data': request.POST})

        # Handle existing email cases
        if email:
            existing_user = User.objects.filter(email=email).first()
            if existing_user:
                if existing_user.email_verified:
                    messages.error(request, 'Email already registered.')
                    return render(request, 'client_register.html', {'post_data': request.POST})
                else:
                    # Email exists but not verified - update user details and resend verification
                    try:
                        existing_user.first_name = first_name
                        existing_user.last_name = last_name
                        existing_user.phone_number = phone_number
                        existing_user.sex = sex
                        existing_user.current_address = current_address
                        existing_user.birthday = birthday
                        existing_user.age = age
                        existing_user.set_password(password)
                        existing_user.generate_email_verification_token()
                        existing_user.save()

                        # Send new verification email
                        verification_link = request.build_absolute_uri(
                            reverse('client_verify_email', args=[existing_user.email_verification_token])
                        )
                        html_message = render_to_string('email_verification_template.html', {
                            'user': existing_user,
                            'verification_link': verification_link,
                        })
                        plain_message = strip_tags(html_message)

                        send_mail(
                            subject='Verify Your Email - Jaylon Dental Clinic',
                            message=plain_message,
                            from_email=settings.EMAIL_HOST_USER,
                            recipient_list=[existing_user.email],
                            html_message=html_message,
                            fail_silently=False,
                        )
                        messages.success(request, 'A new verification email has been sent. Please check your email.')
                        return redirect('client_login')
                    except Exception as e:
                        messages.error(request, 'Failed to send verification email. Please try again.')
                        return render(request, 'client_register.html', {'post_data': request.POST})

        # Handle existing phone number cases
        if phone_number:
            existing_user = User.objects.filter(phone_number=phone_number).first()
            if existing_user:
                if existing_user.phone_verified:
                    messages.error(request, 'Phone number already registered.')
                    return render(request, 'client_register.html', {'post_data': request.POST})
                else:
                    # Phone exists but not verified - update user details and resend verification
                    try:
                        existing_user.first_name = first_name
                        existing_user.last_name = last_name
                        existing_user.email = email
                        existing_user.sex = sex
                        existing_user.current_address = current_address
                        existing_user.birthday = birthday
                        existing_user.age = age
                        existing_user.set_password(password)
                        existing_user.generate_phone_verification_code()
                        existing_user.save()

                        payload = {
                            'apikey': settings.SEMAPHORE_API_KEY,
                            'number': phone_number,
                            'message': f'Your verification code is: {existing_user.phone_verification_code}',
                            'sendername': settings.SEMAPHORE_SENDER_NAME
                        }

                        base_url = 'https://api.semaphore.co/api/v4/messages'
                        response = requests.post(base_url, json=payload)

                        if response.status_code == 200:
                            messages.success(request, 'A new verification code has been sent to your phone.')
                            return redirect('client_verify_phone', phone_number=phone_number)
                        else:
                            messages.error(request, 'Failed to send SMS verification. Please try again.')
                            return render(request, 'client_register.html', {'post_data': request.POST})
                    except Exception as e:
                        messages.error(request, 'Failed to send verification code. Please try again.')
                        return render(request, 'client_register.html', {'post_data': request.POST})

        # Create new user if no existing unverified account found
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
        # Set identifier based on what's provided
        user.identifier = email if email else phone_number
        user.set_password(password)

        # Handle email verification for new user
        if email:
            user.generate_email_verification_token()
            user.save()

            try:
                verification_link = request.build_absolute_uri(
                    reverse('client_verify_email', args=[user.email_verification_token])
                )
                html_message = render_to_string('email_verification_template.html', {
                    'user': user,
                    'verification_link': verification_link,
                })
                plain_message = strip_tags(html_message)

                send_mail(
                    subject='Verify Your Email - Jaylon Dental Clinic',
                    message=plain_message,
                    from_email=settings.EMAIL_HOST_USER,
                    recipient_list=[user.email],
                    html_message=html_message,
                    fail_silently=False,
                )
                messages.success(request,
                                 'Registration successful. Please check your email to verify your account.')
                return redirect('client_login')
            except Exception as e:
                user.delete()
                messages.error(request, 'Failed to send verification email. Please try again.')
                return render(request, 'client_register.html', {'post_data': request.POST})

        # Handle phone verification for new user
        else:
            user.generate_phone_verification_code()
            user.save()

            try:
                payload = {
                    'apikey': settings.SEMAPHORE_API_KEY,
                    'number': phone_number,
                    'message': f'Your verification code is: {user.phone_verification_code}',
                    'sendername': settings.SEMAPHORE_SENDER_NAME
                }

                base_url = 'https://api.semaphore.co/api/v4/messages'
                response = requests.post(base_url, json=payload)

                if response.status_code == 200:
                    messages.success(request, 'Verification code sent to your phone.')
                    return redirect('client_verify_phone', phone_number=phone_number)
                else:
                    user.delete()
                    messages.error(request, 'Failed to send SMS verification. Please try again.')
                    return render(request, 'client_register.html', {'post_data': request.POST})
            except Exception as e:
                user.delete()
                messages.error(request, 'Failed to send SMS verification. Please try again.')

    return render(request, 'client_register.html')


def verify_phone(request, phone_number):
    if request.method == 'POST':
        code = request.POST.get('verification_code')
        try:
            user = User.objects.get(phone_number=phone_number, phone_verification_code=code)

            if user.phone_verification_code_created:
                code_age = timezone.localtime(timezone.now()) - user.phone_verification_code_created
                if code_age > timedelta(hours=24):
                    messages.error(request, 'Code expired. Request new code.')
                    # Redirect based on whether this is for password reset or registration
                    return redirect('client_forgot_password' if user.password_reset_token else 'client_register')

            # Check if this is a password reset verification
            if user.password_reset_token == 'pending':
                # Generate the actual reset token
                token = get_random_string(length=32)
                user.password_reset_token = token
                user.password_reset_token_created = timezone.localtime(timezone.now())
                user.phone_verification_code = None
                user.phone_verification_code_created = None
                user.save()
                return redirect('client_reset_password', token=token)

            # Otherwise, this is a new user verification flow
            else:
                user.phone_verified = True
                user.phone_verification_code = None
                user.phone_verification_code_created = None
                user.save()
                messages.success(request, 'Your phone number has been verified. You can now log in.')
                return redirect('client_login')

        except User.DoesNotExist:
            messages.error(request, 'Invalid code.')
    return render(request, 'verify_phone.html')


def verify_email(request, token):
    try:
        user = User.objects.get(email_verification_token=token)

        # Check if the verification token has a creation time
        if user.email_verification_token_created:
            token_age = timezone.localtime(timezone.now()) - user.email_verification_token_created
            if token_age > timedelta(hours=24):
                messages.error(request, 'Verification link has expired. Please request a new one.')
                return redirect('client_register')
        else:
            # If there's no creation time, we can't verify the token age
            messages.error(request, 'Invalid verification token. Please request a new one.')
            return redirect('client_register')

        # If we get here, the token is valid
        user.email_verified = True
        user.email_verification_token = None
        user.email_verification_token_created = None
        user.save()
        messages.success(request, 'Your email has been verified. You can now log in.')
        return redirect('client_login')
    except User.DoesNotExist:
        messages.error(request, 'Invalid verification token.')
        return redirect('client_login')


def client_forgot_password(request):
    if request.method == 'POST':
        identifier = request.POST.get('email_or_phone')
        try:
            # Check if the identifier is an email
            if '@' in identifier:
                user = User.objects.get(email=identifier, is_superuser=False)
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

            else:
                # Handle phone number case
                user = User.objects.get(phone_number=identifier, is_superuser=False)
                # Generate verification code
                user.generate_phone_verification_code()
                # Set a temporary token to identify this as a password reset flow
                user.password_reset_token = 'pending'
                user.password_reset_token_created = timezone.localtime(timezone.now())
                user.save()

                # Send SMS with verification code
                payload = {
                    'apikey': settings.SEMAPHORE_API_KEY,
                    'number': identifier,
                    'message': f'Your password reset code is: {user.phone_verification_code}',
                    'sendername': settings.SEMAPHORE_SENDER_NAME
                }

                response = requests.post('https://api.semaphore.co/api/v4/messages', json=payload)

                if response.status_code == 200:
                    messages.success(request, 'Password reset code has been sent to your phone.')
                    return redirect('client_verify_phone', phone_number=identifier)
                else:
                    messages.error(request, 'Failed to send SMS verification. Please try again.')
                    return redirect('client_forgot_password')

        except User.DoesNotExist:
            messages.error(request, 'No user found with the provided email/phone number.')

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
