FROM python:3.9
ENV PYTHONUNBUFFERED 1
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# create the user coker with uid 1000 to grant priv to feyin
ARG user=coker
ARG group=docker
ARG uid=1000
ARG gid=1001
ENV WEB_HOME /usr/src/app/
RUN groupadd -g ${gid} ${group}
RUN useradd -u ${uid} -g ${group} -s /bin/sh -m ${user} # <--- the '-m' create a user home directory

# Switch to user

WORKDIR .:/usr/src/app/
#RUN pwd # git clone --branch 4.2 --single-branch --depth 1 https:......url && chown -R bind mount data:www/ht
COPY requirements.txt ./
RUN  pip install -r requirements.txt

COPY . .
EXPOSE 8000
CMD ./manage.py collectstatic --noinput && ./manage.py migrate
# Switch to user
USER ${uid}:${gid}
#CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
CMD ["gunicorn", "--bind", ":8000", "--workers", "2", "clean_code.wsgi:application"]

# mount the host volume to the container volume
# docker run -v /home/feyintoluwa/PycharmProjects/clean_code/.:/usr/src/app/ clean_code_web 


