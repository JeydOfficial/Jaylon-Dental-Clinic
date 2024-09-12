from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

from backend.cron_views import cancel_unattended_appointments

urlpatterns = [
    path('main-admin/', admin.site.urls),
    path('admin/', include('backend.urls')),
    path('', include('frontend.urls')),
    path('api/cron/cancel_appointments', cancel_unattended_appointments),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
