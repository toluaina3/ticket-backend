# Generated by Django 3.1.1 on 2020-10-22 23:29

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('request', '0010_sla'),
    ]

    operations = [
        migrations.AddField(
            model_name='user_request_table',
            name='sla_request',
            field=models.ForeignKey(default=1, on_delete=django.db.models.deletion.CASCADE, related_name='sla_request', to='request.sla'),
            preserve_default=False,
        ),
    ]
