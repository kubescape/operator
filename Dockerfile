FROM alpine:latest

# COPY ./dist /. 
# COPY ./build_number.txt / 
RUN apk update && apk add ca-certificates

# COPY ./dist /.
# COPY ./build_number.txt /

RUN apk update && apk add ca-certificates && apk add python3 
RUN pip3 install cacli --index-url https://cacustomer:x4qfg=4qip1r6t@d@carepo.system.cyberarmorsoft.com/repository/cyberarmor-pypi-dev.group/simple

COPY ./k8s-ca-websocket . 
CMD /k8s-ca-websocket
ENTRYPOINT ["./k8s-ca-websocket"]
