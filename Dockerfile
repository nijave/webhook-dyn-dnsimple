FROM docker.io/library/python:3-alpine

RUN pip3 install -U pip setuptools wheel \
    && apk add gcc musl-dev

COPY requirements.txt /tmp/requirements.txt
RUN pip3 install -r /tmp/requirements.txt

WORKDIR /app
COPY run.sh *.py /app/

EXPOSE 8080
CMD /app/run.sh
