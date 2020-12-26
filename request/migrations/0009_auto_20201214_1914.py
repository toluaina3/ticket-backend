# Generated by Django 3.1.1 on 2020-12-14 18:14

from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('request', '0008_auto_20201207_2154'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='request_table',
            name='request_response',
        ),
        migrations.AlterField(
            model_name='response_table',
            name='response',
            field=models.TextField(help_text='Message to client', max_length=1000, verbose_name='Message'),
        ),
        migrations.CreateModel(
            name='ticket_message_table',
            fields=[
                ('ticket_uuid_message', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('ticket_message', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='ticket_response_relation', to='request.response_table')),
                ('ticket_request', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='ticket_request_relation', to='request.request_table')),
            ],
        ),
    ]
