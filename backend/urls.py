from django.urls import path
from .views import *

urlpatterns = [
    path('', appointment_dashboard, name='appointment_dashboard'),
    path('appointment_history/', appointment_history, name='appointment_history'),
    path('login/', user_login, name='login'),
    path('forgot-password/', forgot_password, name='forgot_password'),
    path('reset-password/<str:token>/', reset_password, name='reset_password'),
    path('logout/', user_logout, name='logout'),
    path('gallery/', upload_image, name='gallery'),
    path('delete-image/<int:image_id>/', delete_image, name='delete_image'),
    path('services/', service_operations, name='services'),
    path('delete-service/<int:service_id>/', delete_service, name='delete_service'),
    path('accounts/', view_accounts, name='accounts'),
    path('delete-user/<int:user_id>/', delete_user, name='delete_user'),
    path('user/<int:user_id>/', user_details, name='user_details'),

    path('delete-appointment/<int:appointment_id>/', delete_appointment, name='delete_appointment'),
    path('update-appointment-status/<int:appointment_id>/', update_appointment_status,
         name='update_appointment_status'),
    path('update-appointment-attendance/<int:appointment_id>/', update_appointment_attendance,
         name='update_appointment_attendance'),

    path('admin-profile/', admin_profile, name='admin_profile'),

    path('get-available-time-slots/', get_available_time_slots, name='get_available_time_slots'),

]
