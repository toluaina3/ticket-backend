# Generated by Django 3.1 on 2020-09-23 16:22

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('request', '0002_auto_20200923_1721'),
    ]

    operations = [
        migrations.AlterField(
            model_name='roles_table',
            name='role',
            field=models.CharField(choices=[('User', 'User'), ('IT team', 'IT team'), ('Admin', 'Admin')], default='User', max_length=7),
        ),
    ]