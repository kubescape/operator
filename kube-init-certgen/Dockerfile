FROM alpine/k8s:1.36.1@sha256:692239d739589247c4a791205ed9619c28ae85a21286e19a6211c04a62c56668

RUN apk add --no-cache openssl && \
    addgroup -S certgen && \
    adduser -S -G certgen certgen

COPY scripts/ /scripts/
RUN chmod +x /scripts/*.sh && \
    chown -R certgen:certgen /scripts

USER certgen
WORKDIR /scripts