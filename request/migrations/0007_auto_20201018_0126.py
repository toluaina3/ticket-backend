# Generated by Django 3.1.1 on 2020-10-18 00:26

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('request', '0006_auto_20201014_1234'),
    ]

    operations = [
        migrations.AlterField(
            model_name='request_table',
            name='assigned_to',
            field=models.CharField(blank=True, default='None', max_length=40),
        ),
        migrations.AlterField(
            model_name='request_table',
            name='close_request',
            field=models.CharField(blank=True, choices=[('Closed', 'Closed'), ('Cancelled', 'Cancelled'), ('Open', 'Open'), ('Completed', 'Completed')], default='Open', max_length=15),
        ),
    ]