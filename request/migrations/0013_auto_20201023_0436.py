# Generated by Django 3.1.1 on 2020-10-23 03:36

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('request', '0012_auto_20201023_0435'),
    ]

    operations = [
        migrations.RenameField(
            model_name='request_table',
            old_name='sla_request',
            new_name='sla_category',
        ),
    ]