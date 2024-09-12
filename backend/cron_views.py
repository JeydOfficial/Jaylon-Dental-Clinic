from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from datetime import timedelta
from .models import Appointment
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.conf import settings


@csrf_exempt
@require_http_methods(["GET", "POST", "HEAD"])
def cancel_unattended_appointments(request):
    if request.method in ['POST', 'GET', 'HEAD']:
        today = timezone.localtime(timezone.now())
        yesterday = today - timedelta(days=1)

        unattended_appointments = Appointment.objects.filter(
            status='Approved',
            attended=False,
            date=yesterday
        )

        cancelled_count = 0
        for appointment in unattended_appointments:
            appointment.status = 'Cancelled'
            appointment.save()
            cancelled_count += 1

            # Send an email notification
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

        return HttpResponse(f"Cancelled {cancelled_count} unattended appointments.")
    else:
        return HttpResponse("This endpoint only accepts GET, POST, and HEAD requests.", status=405)