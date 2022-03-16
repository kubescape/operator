# FROM python:3.8.0-alpine
FROM alpine:3.15
RUN rm -rf /tmp/*
FROM scratch

COPY --from=0 /etc/ssl/certs /etc/ssl/certs
COPY --from=0 /tmp /tmp
# RUN mkdir .ca && chmod -R 777 .ca

# COPY ./dist /.
COPY ./k8s-ca-websocket . 
COPY ./build_date.txt . 

COPY ./build_number.txt /

# RUN echo $(date -u) > ./build_date.txt
ENTRYPOINT ["./k8s-ca-websocket"]
