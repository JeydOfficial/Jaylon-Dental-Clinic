# Generated by Django 4.2.15 on 2024-12-25 22:20

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('backend', '0032_appointment_other_concern'),
    ]

    operations = [
        migrations.RenameField(
            model_name='appointment',
            old_name='other_concern',
            new_name='custom_concern',
        ),
    ]
