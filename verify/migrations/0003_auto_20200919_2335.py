# Generated by Django 3.1 on 2020-09-19 22:35

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('verify', '0002_auto_20200906_1129'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='is_staff',
            field=models.BooleanField(default=False, help_text='IT Team', verbose_name='IT Team'),
        ),
    ]