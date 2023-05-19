FROM python:3.8.13-alpine3.16

ENV PYTHONUNBUFFERED=TRUE

RUN apk update && apk add --no-cache  tzdata git make  build-base
RUN apk upgrade -U \
    && apk add --no-cache -u ca-certificates libva-intel-driver mpc1-dev libffi-dev build-base supervisor python3-dev build-base linux-headers pcre-dev curl busybox-extras \
    && rm -rf /tmp/* /var/cache/* 

WORKDIR /webapps
COPY . /webapps
RUN pip install -r requirements.txt
CMD ["python", "main.py"]