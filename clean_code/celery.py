from __future__ import absolute_import
import os
from celery import Celery
from celery.schedules import crontab
from django.conf import settings

# from celery.schedules import crontab

# set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'clean_code.settings')
app = Celery('clean_code', broker='redis://user:$$ticket@192.100.0.6:6379',
             backend='redis://user:$$ticket@192.100.0.6:6379', include=['clean_code.tasks'])

# Using a string here means the worker will not have to
# pickle the object when using Windows.
app.config_from_object('django.conf:settings')
app.autodiscover_tasks(lambda: settings.INSTALLED_APPS)
app.conf.update(CELERY_TASK_SERIALIZER='json', CELERY_RESULT_SERIALIZER='json', CELERY_TASK_RESULT_EXPIRES=3600,
                CELERY_TIMEZONE='Africa/Lagos', CELERYBEAT_SCHEDULE=
                {'overdue_request_email': {'task': 'clean_code.tasks.response_time_sla',
                                           'schedule': crontab(minute='*/5'), }, }, )


@app.task(bind=True)
def debug_task(self):
    print('Request: {0!r}'.format(self.request))
if __name__ == '__main__':
    app.start()