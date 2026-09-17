from django.contrib import admin

from backend.models import *

# Register your models here.
admin.site.register(User)
admin.site.register(GalleryImage)
admin.site.register(Service)
admin.site.register(Appointment)
admin.site.register(MedicalQuestionnaire)
