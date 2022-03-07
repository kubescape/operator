FROM alpine:3.15
# FROM python:3.8.0-alpine

RUN apk update
RUN apk add ca-certificates 

# RUN pip3 install --upgrade pip
# RUN pip3 install -U cacli --index-url https://carepo.system.cyberarmorsoft.com/repository/cyberarmor-pypi-dev.group/simple

RUN mkdir .ca && chmod -R 777 .ca

# COPY ./dist /.
COPY ./k8s-ca-websocket . 

COPY ./build_number.txt /

RUN echo $(date -u) > ./build_date.txt
ENTRYPOINT ["./k8s-ca-websocket"]
