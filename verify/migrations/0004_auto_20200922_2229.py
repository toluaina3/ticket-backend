# Generated by Django 3.1 on 2020-09-22 21:29

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('verify', '0003_auto_20200919_2335'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='email',
            field=models.EmailField(max_length=100, unique=True, verbose_name='Email Address'),
        ),
    ]