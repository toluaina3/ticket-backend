FROM python:3.8.5
#ENV PYTHONUNBUFFERED 1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# create the user coker with uid 1000 to grant priv to feyin
ARG user=feyintoluwa
ARG group=feyintoluwa
ARG uid=1000
ARG gid=1000
ENV WEB_HOME /usr/src/app/
RUN groupadd -g ${gid} ${group} \
    && useradd -d "$WEB_HOME" -u ${uid} -g ${gid} -m -s /bin/bash ${user}c

WORKDIR .:/usr/src/app/
#RUN pwd # git clone --branch 4.2 --single-branch --depth 1 https:......url && chown -R bind mount data:www/ht
COPY requirements.txt ./
RUN  pip install -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]

# mount the host volume to the container volume
# docker run -v /home/feyintoluwa/PycharmProjects/clean_code/.:/usr/src/app/ clean_code_web 


