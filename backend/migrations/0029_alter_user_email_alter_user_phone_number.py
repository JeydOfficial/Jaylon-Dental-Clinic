# Generated by Django 4.2.15 on 2024-10-31 10:25

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('backend', '0028_alter_user_email_alter_user_phone_number'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='email',
            field=models.EmailField(blank=True, max_length=254, null=True, unique=True),
        ),
        migrations.AlterField(
            model_name='user',
            name='phone_number',
            field=models.CharField(blank=True, max_length=15, null=True),
        ),
    ]
