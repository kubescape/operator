FROM alpine:3.11

RUN apk update
RUN apk add ca-certificates && apk add python3 

RUN pip3 install --upgrade pip
RUN pip3 install -U cacli --index-url https://@carepo.system.cyberarmorsoft.com/repository/cyberarmor-pypi-dev.group/simple

RUN mkdir .ca && chmod -R 777 .ca

COPY ./dist /.
COPY ./build_number.txt /

RUN echo $(date -u) > /build_date.txt

ENTRYPOINT ["./k8s-ca-websocket"]
