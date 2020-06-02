FROM alpine:3.11

RUN apk update
RUN apk add ca-certificates && apk add python3 

RUN pip3 install --upgrade pip
RUN pip3 install -U cacli --index-url https://cacustomer:x4qfg=4qip1r6t@d@carepo.system.cyberarmorsoft.com/repository/cyberarmor-pypi-dev.group/simple

COPY ./dist /.
COPY ./build_number.txt /

RUN echo $(date -u) > /build_date.txt

CMD /k8s-ca-websocket
ENTRYPOINT ["./k8s-ca-websocket"]
