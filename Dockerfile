FROM python:3.8.5
#ENV PYTHONUNBUFFERED 1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        postgresql-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR .:/usr/src/app/
#RUN pwd # git clone --branch 4.2 --single-branch --depth 1 https:......url && chown -R bind mount data:www/ht
COPY requirements.txt ./
RUN  pip install -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
