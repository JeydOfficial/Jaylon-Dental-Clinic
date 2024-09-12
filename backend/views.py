from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.core.mail import send_mail
from django.db.models.functions import TruncMonth, TruncDay
from django.http import HttpResponseRedirect, JsonResponse
from django.shortcuts import render, redirect
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils import timezone
from django.utils.crypto import get_random_string
from django.utils.html import strip_tags
from django.views.decorators.http import require_GET
from datetime import datetime, timedelta
from django.core.cache import cache
from django.db.models import Count, Q, Max

from backend.models import GalleryImage, Service, User, Appointment, MedicalQuestionnaire


def user_login(request):
    # Check if the user is already authenticated
    if request.user.is_authenticated and request.user.is_superuser:
        return redirect('dashboard')  # Redirect to the dashboard if logged in

    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        # Authenticate the user
        user = authenticate(request, email=email, password=password)

        if user is not None:
            if user.is_superuser:  # Check if the user has admin privileges
                login(request, user)
                return redirect('dashboard')  # Redirect to the admin dashboard or desired page
            else:
                messages.error(request, 'You do not have permission to access this page.')
        else:
            messages.error(request, 'Invalid username or password.')

    return render(request, 'login.html')


@login_required(login_url='login')
def admin_profile(request):
    if not request.user.is_superuser:
        return redirect('login')

    if request.method == 'POST':
        new_email = request.POST.get('email')
        new_password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        if new_password != confirm_password:
            messages.error(request, 'Passwords do not match.')
            return redirect('admin_profile')

        user = request.user
        if User.objects.filter(email=new_email).exclude(id=user.id).exists():
            messages.error(request, 'Email is already in use.')
            return redirect('admin_profile')

        user.email = new_email
        if new_password:
            user.set_password(new_password)
        user.save()

        messages.success(request, 'Profile updated successfully. Please login.')
        logout(request)
        return redirect('login')

    return render(request, 'admin_profile.html')


def forgot_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            user = User.objects.get(email=email, is_superuser=True)
            # Generate a random token
            token = get_random_string(length=32)
            user.password_reset_token = token
            user.password_reset_token_created = datetime.now()
            user.save()

            # Send password reset email
            reset_link = request.build_absolute_uri(
                reverse('reset_password', args=[token])
            )

            html_message = render_to_string('admin_password_reset_email_template.html', {
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
            return redirect('login')
        except User.DoesNotExist:
            messages.error(request, 'No admin user with that email address exists.')

    return render(request, 'forgot_password.html')


def reset_password(request, token):
    try:
        user = User.objects.get(password_reset_token=token, is_superuser=True)
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
                return redirect('login')
            else:
                messages.error(request, 'Passwords do not match.')
        return render(request, 'reset_password.html')
    except User.DoesNotExist:
        messages.error(request, 'Invalid password reset token.')
        return redirect('login')


@login_required(login_url='login')
def user_logout(request):
    logout(request)
    return redirect('login')  # Redirect to the login page after logout


def get_operating_hours(date):
    """
    Returns the operating hours for a given date.
    """
    if date.weekday() == 6:  # Sunday
        return datetime.combine(date, datetime.min.time().replace(hour=9, minute=0)), \
               datetime.combine(date, datetime.min.time().replace(hour=13, minute=0))
    else:  # Monday to Saturday
        return datetime.combine(date, datetime.min.time().replace(hour=6, minute=0)), \
               datetime.combine(date, datetime.min.time().replace(hour=16, minute=0))


@require_GET
def get_available_time_slots(request):
    service_id = request.GET.get('service_id')
    date = request.GET.get('date')

    service = Service.objects.get(pk=service_id)
    selected_date = datetime.strptime(date, '%Y-%m-%d').date()

    # Get operating hours for the selected date
    start_time, end_time = get_operating_hours(selected_date)

    # Define lunch break
    lunch_start = datetime.combine(selected_date, datetime.min.time().replace(hour=12, minute=0))
    lunch_end = datetime.combine(selected_date, datetime.min.time().replace(hour=13, minute=0))

    # Get all non-cancelled appointments for the selected date
    appointments = Appointment.objects.filter(date=selected_date, status__in=['Pending', 'Approved']).order_by(
        'start_time')

    # Create a list of busy time slots, including lunch break
    busy_slots = [(datetime.combine(selected_date, apt.start_time),
                   datetime.combine(selected_date, apt.end_time))
                  for apt in appointments]
    busy_slots.append((lunch_start, lunch_end))  # Add lunch break to busy slots
    busy_slots.sort(key=lambda x: x[0])  # Sort busy slots

    available_slots = []
    current_time = start_time

    while current_time + timedelta(minutes=service.duration) <= end_time:
        slot_end = current_time + timedelta(minutes=service.duration)
        is_available = True

        for busy_start, busy_end in busy_slots:
            if (current_time < busy_end and slot_end > busy_start):
                is_available = False
                current_time = busy_end
                break

        if is_available:
            available_slots.append({
                'start': current_time.strftime('%I:%M %p'),
                'end': slot_end.strftime('%I:%M %p')
            })
            current_time += timedelta(minutes=service.duration)
        elif not is_available and current_time == busy_end:
            # If we've jumped to the end of a busy slot, don't increment further
            continue
        else:
            # If not available and not at the end of a busy slot, increment by the service duration
            current_time += timedelta(minutes=service.duration)

    return JsonResponse({'available_slots': available_slots})


@login_required(login_url='login')
def view_dashboard(request):
    if not request.user.is_superuser:
        return redirect('login')

    # Get current date
    today = timezone.localtime(timezone.now()).date()

    # Use select_related to reduce database queries
    appointments = Appointment.objects.select_related('user', 'service').all()

    # Use database aggregation for appointment counts
    appointment_stats = Appointment.objects.aggregate(
        all_appointments=Count('id'),
        todays_appointments=Count('id', filter=Q(date=today)),
        pending_appointments=Count('id', filter=Q(status='Pending')),
        approved_appointments=Count('id', filter=Q(status='Approved')),
        cancelled_appointments=Count('id', filter=Q(status='Cancelled')),
        done_appointments=Count('id', filter=Q(status='Approved', attended=True))
    )

    # Optimize monthly data query and caching
    monthly_chart_data = cache.get('monthly_chart_data')
    if not monthly_chart_data:
        latest_date = Appointment.objects.aggregate(latest=Max('date'))['latest'] or today
        start_date = latest_date - timedelta(days=365)

        monthly_data = (Appointment.objects
                        .filter(date__gte=start_date, status='Approved')
                        .annotate(month=TruncMonth('date'))
                        .values('month')
                        .annotate(total=Count('id'))
                        .order_by('month'))

        months = [data['month'].strftime('%B %Y') for data in monthly_data]
        monthly_totals = [data['total'] for data in monthly_data]
        monthly_chart_data = {'months': months, 'monthly_totals': monthly_totals}
        cache.set('monthly_chart_data', monthly_chart_data, 3600)  # Cache for 1 hour

    # Optimize daily data query and caching
    daily_chart_data = cache.get('daily_chart_data')
    if not daily_chart_data:
        start_date_7_days = today - timedelta(days=7)
        daily_data = (Appointment.objects
                      .filter(date__range=[start_date_7_days, today], status='Approved')
                      .annotate(day=TruncDay('date'))
                      .values('day')
                      .annotate(total=Count('id'))
                      .order_by('day'))

        days = [data['day'].strftime('%A') for data in daily_data]
        daily_totals = [data['total'] for data in daily_data]
        daily_chart_data = {'days': days, 'daily_totals': daily_totals}
        cache.set('daily_chart_data', daily_chart_data, 3600)  # Cache for 1 hour

    context = {
        'users': User.objects.filter(is_superuser=False, email_verified=True),
        'services': Service.objects.all(),
        'appointments': appointments,
        **appointment_stats,
        **monthly_chart_data,
        **daily_chart_data,
    }

    if request.method == 'POST':
        # Handle form submission (appointment creation)
        user_id = request.POST.get('user')
        service_id = request.POST.get('service')
        date = request.POST.get('date')
        time_slot = request.POST.get('time_slot')
        status = request.POST.get('status')

        user = User.objects.get(pk=user_id)
        service = Service.objects.get(pk=service_id)

        start_time, end_time = time_slot.split(' - ')
        start_time = datetime.strptime(start_time, '%I:%M %p').time()
        end_time = datetime.strptime(end_time, '%I:%M %p').time()

        appointment = Appointment(
            user=user,
            service=service,
            date=date,
            start_time=start_time,
            end_time=end_time,
            status=status,
        )
        appointment.save()

        messages.success(request, 'Appointment added successfully.')
        return redirect('dashboard')

    return render(request, 'dashboard.html', context)


@login_required(login_url='login')
def upload_image(request):
    # Check if the user is not admin
    if not request.user.is_superuser:
        return redirect('login')

    if request.method == 'POST':
        image = request.FILES.get('image')
        gallery_image = GalleryImage(image=image)
        gallery_image.save()
        messages.success(request, 'Image uploaded successfully.')
        return redirect('gallery')

    images = GalleryImage.objects.all()
    return render(request, 'gallery.html', {'images': images})


@login_required(login_url='login')
def delete_image(request, image_id):
    # Check if the user is not admin
    if not request.user.is_superuser:
        return redirect('login')

    image = GalleryImage.objects.get(pk=image_id)
    image.delete()
    messages.success(request, 'Image deleted successfully.')
    return redirect('gallery')


@login_required(login_url='login')
def service_operations(request):
    # Check if the user is not admin
    if not request.user.is_superuser:
        return redirect('login')

    if request.method == 'POST':
        # Check if an 'id' is provided to identify if it's an edit operation
        service_id = request.POST.get('service_id')

        # Add or Update Service
        if service_id:
            # Editing an existing service
            service = Service.objects.get(pk=service_id)
            title = request.POST.get('title')
            description = request.POST.get('description')
            duration = request.POST.get('duration')
            image = request.FILES.get('image')

            # Update the service fields
            service.title = title
            service.description = description
            service.duration = int(duration)

            # Only update image if a new file is uploaded
            if image:
                service.image = image

            # Save the updated service
            service.save()

            messages.success(request, 'Service updated successfully!')
        else:
            # Adding a new service
            title = request.POST.get('title')
            description = request.POST.get('description')
            duration = request.POST.get('duration')
            image = request.FILES.get('image')

            # Create a new Service instance
            service = Service(
                title=title,
                description=description,
                duration=int(duration),
                image=image
            )
            service.save()

            messages.success(request, 'Service added successfully!')

        return redirect('services')  # Redirect to the services page

    services = Service.objects.all()
    return render(request, 'services.html', {'services': services})


@login_required(login_url='login')
def delete_service(request, service_id):
    # Check if the user is not admin
    if not request.user.is_superuser:
        return redirect('login')

    service = Service.objects.get(pk=service_id)
    service.delete()
    messages.success(request, 'Service deleted successfully.')
    return redirect('services')


@login_required(login_url='login')
def view_accounts(request):
    # Check if the user is not admin
    if not request.user.is_superuser:
        return redirect('login')

    users = User.objects.filter(is_superuser=False, email_verified=True)  # Retrieve all user records

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
            return redirect('accounts')

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
            email_verified=True,
        )
        user.set_password(password)
        user.save()
        messages.success(request, 'User registered successfully!')
        return redirect('accounts')

    return render(request, 'accounts.html', {'users': users})


@login_required(login_url='login')
def delete_user(request, user_id):
    # Check if the user is not admin
    if not request.user.is_superuser:
        return redirect('login')

    user = User.objects.get(pk=user_id)
    user.delete()
    messages.success(request, 'User deleted successfully.')
    return redirect('accounts')


@login_required(login_url='login')
def user_details(request, user_id):
    # Check if the user is not admin
    if not request.user.is_superuser:
        return redirect('login')

    user = User.objects.get(pk=user_id)
    appointments = Appointment.objects.filter(user_id=user_id)
    services = Service.objects.all()  # Assuming you have a Service model

    if request.method == 'POST':
        if 'service' in request.POST:
            # Extract appointment data from POST request
            service_id = request.POST.get('service')
            appointment_date = request.POST.get('date')
            appointment_time_slot = request.POST.get('time_slot')
            appointment_status = request.POST.get('status')

            service = Service.objects.get(pk=service_id)

            # Parse the time slot
            start_time, end_time = appointment_time_slot.split(' - ')
            start_time = datetime.strptime(start_time, '%I:%M %p').time()
            end_time = datetime.strptime(end_time, '%I:%M %p').time()

            # Create and save the new appointment
            appointment = Appointment(
                user=user,
                service=service,
                date=appointment_date,
                start_time=start_time,
                end_time=end_time,
                status=appointment_status
            )
            appointment.save()
            messages.success(request, 'Appointment created successfully!')

        else:
            # Existing code for updating user details
            new_first_name = request.POST.get('first_name')
            new_last_name = request.POST.get('last_name')
            new_email = request.POST.get('email')
            new_phone_number = request.POST.get('phone_number')
            new_sex = request.POST.get('sex')
            new_current_address = request.POST.get('current_address')
            new_birthday = request.POST.get('birthday')
            new_age = request.POST.get('age')
            new_password = request.POST.get('password')
            confirm_new_password = request.POST.get('confirm_password')

            # Check if the new email is already taken by another user
            if User.objects.filter(email=new_email).exclude(id=user.id).exists():
                messages.error(request, 'Email is already registered.')
                return redirect('user_details', user_id)

            # Update user details
            user.first_name = new_first_name
            user.last_name = new_last_name
            user.email = new_email
            user.phone_number = new_phone_number
            user.sex = new_sex
            user.current_address = new_current_address
            user.birthday = new_birthday
            user.age = new_age
            user.email_verified = True

            # Check if passwords are being updated
            if new_password:
                # Check if passwords match
                if new_password != confirm_new_password:
                    messages.error(request, 'Passwords do not match.')
                    return redirect('user_details', user_id)
                user.set_password(new_password)

            user.save()
            messages.success(request, 'User details updated successfully!')
            return redirect('user_details', user_id)  # Redirect back to the accounts list

    try:
        medical_questionnaire = MedicalQuestionnaire.objects.get(user=user)
        medical_questionnaire_data = [
            ("Are you under physician's care?", medical_questionnaire.physician_care),
            ("Do you have high blood pressure?", medical_questionnaire.high_blood_pressure),
            ("Do you have heart disease?", medical_questionnaire.heart_disease),
            ("Are you allergic to any drugs, medicine, foods, anesthetics?", medical_questionnaire.allergic),
            ("Do you have diabetes?", medical_questionnaire.diabetes),
            ("Do you have any blood disease?", medical_questionnaire.blood_disease),
            ("Are you a bleeder?", medical_questionnaire.bleeder),
            ("Have you experienced excessive bleeding after tooth extraction?", medical_questionnaire.excessive_bleeding),
            ("Have you or have you recently had evidence of infection such as boils, infected wounds?", medical_questionnaire.recent_infection),
            ("Have you ever had any reactions from local anesthetics?", medical_questionnaire.anesthetic_reactions),
            ("Have you had any dental surgery before?", medical_questionnaire.previous_dental_surgery),
            ("What is your impression of your present health?", medical_questionnaire.health_impression),
        ]
    except MedicalQuestionnaire.DoesNotExist:
        medical_questionnaire = None
        medical_questionnaire_data = []

    context = {
        'user': user,
        'appointments': appointments,
        'services': services,
        'medical_questionnaire': medical_questionnaire,
        'medical_questionnaire_data': medical_questionnaire_data,
    }
    return render(request, 'user_details.html', context)


@login_required(login_url='login')
def delete_appointment(request, appointment_id):
    # Check if the user is not admin
    if not request.user.is_superuser:
        return redirect('login')

    appointment = Appointment.objects.get(pk=appointment_id)
    appointment.delete()
    messages.success(request, 'Appointment deleted successfully.')

    # Get the URL of the referring page
    referer = request.META.get('HTTP_REFERER', '/')
    # Redirect back to the referring page
    return HttpResponseRedirect(referer)


@login_required(login_url='login')
def update_appointment_status(request, appointment_id):
    # Check if the user is not admin
    if not request.user.is_superuser:
        return redirect('login')

    appointment = Appointment.objects.get(pk=appointment_id)

    if request.method == 'POST':
        status = request.POST.get('status')
        appointment.status = status
        appointment.save()

        if appointment.status == 'Approved':
            appointment_details_link = request.build_absolute_uri(
                reverse('client_dashboard')
            )

            # Render the HTML template
            html_message = render_to_string('appointment_approval_email_template.html', {
                'appointment': appointment,
                'appointment_details_link': appointment_details_link
            })
            plain_message = strip_tags(html_message)

            send_mail(
                subject='Your Appointment is Approved - Jaylon Dental Clinic',
                message=plain_message,
                from_email=settings.EMAIL_HOST_USER,
                recipient_list=[appointment.user.email],
                html_message=html_message,
                fail_silently=False,
            )

        elif appointment.status == 'Cancelled':

            # Render the HTML template
            html_message = render_to_string('appointment_cancellation_email_template.html', {
                'appointment': appointment
            })
            plain_message = strip_tags(html_message)

            send_mail(
                subject='Appointment Cancellation - Jaylon Dental Clinic',
                message=plain_message,
                from_email=settings.EMAIL_HOST_USER,
                recipient_list=[appointment.user.email],
                html_message=html_message,
                fail_silently=False,
            )
        messages.success(request, 'Appointment status updated successfully.')

    # Get the URL of the referring page
    referer = request.META.get('HTTP_REFERER', '/')
    # Redirect back to the referring page
    return HttpResponseRedirect(referer)


@login_required(login_url='login')
def update_appointment_attendance(request, appointment_id):
    # Check if the user is not admin
    if not request.user.is_superuser:
        return redirect('login')

    appointment = Appointment.objects.get(pk=appointment_id)
    user = appointment.user

    if request.method == 'POST':
        attended = 'attended' in request.POST
        appointment.attended = attended
        appointment.save()

        user.reset_missed_appointments()
        messages.success(request, 'Appointment attendance updated successfully.')

    # Get the URL of the referring page
    referer = request.META.get('HTTP_REFERER', '/')
    # Redirect back to the referring page
    return HttpResponseRedirect(referer)
