FROM alpine:latest

COPY ./dist /. 
COPY ./build_tag.txt / 
COPY ./signingservice/signer_client /signer_client/

RUN apk update && apk add ca-certificates && apk add python3 
RUN cd signer_client && python3 setup.py install && rm -rf /signer_client
 
CMD /k8s-ca-websocket
ENTRYPOINT ["./k8s-ca-websocket"]
