# Generated by Django 4.2.15 on 2024-10-17 23:29

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('backend', '0022_alter_medicalquestionnaire_allergic_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='has_completed_questionnaire',
            field=models.BooleanField(default=False),
        ),
    ]