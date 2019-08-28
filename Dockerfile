FROM alpine:latest

RUN apk update && apk add ca-certificates && apk add python3 
ADD signingservice/signer_client /signer_client/
RUN cd signer_client && python3 setup.py install
RUN rm -rf /signer_client

ADD cawebsocket /cawebsocket
ENTRYPOINT ["./cawebsocket"]


