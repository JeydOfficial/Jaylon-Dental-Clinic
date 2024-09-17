from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from datetime import timedelta
from .models import Appointment
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.conf import settings
import logging

logger = logging.getLogger(__name__)  # Use Django's logger for error handling


@csrf_exempt
@require_http_methods(["GET", "POST", "HEAD"])
def cancel_unattended_appointments(request):
    if request.method in ['POST', 'GET', 'HEAD']:
        today = timezone.localtime(timezone.now())
        yesterday = today - timedelta(days=1)

        # Filtering appointments with a range to ensure full-day coverage.
        unattended_appointments = Appointment.objects.filter(
            status__in=['Pending', 'Approved'],
            attended=False,
            date__range=[yesterday, today]
        )

        cancelled_count = 0
        for appointment in unattended_appointments:
            appointment.status = 'Cancelled'
            appointment.save()  # Save status change

            cancelled_count += 1

            # Send an email notification
            html_message = render_to_string('appointment_cancellation_email_template.html', {
                'appointment': appointment
            })
            plain_message = strip_tags(html_message)

            try:
                send_mail(
                    subject='Appointment Cancellation - Jaylon Dental Clinic',
                    message=plain_message,
                    from_email=settings.EMAIL_HOST_USER,
                    recipient_list=[appointment.user.email],
                    html_message=html_message,
                    fail_silently=False,
                )
            except Exception as e:
                # Log the error and continue
                logger.error(f"Failed to send email for appointment {appointment.id}: {str(e)}")
                # Optionally continue or handle further

        # Return JSON response with cancellation count
        return JsonResponse({'cancelled_count': cancelled_count})

    else:
        return HttpResponse("This endpoint only accepts GET, POST, and HEAD requests.", status=405)
