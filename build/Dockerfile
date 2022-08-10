FROM golang:1.18-alpine as builder

ENV GO111MODULE=

ENV CGO_ENABLED=0

WORKDIR /work
ADD . .

RUN apk add git

WORKDIR /work
RUN go build -o build/kontroller

FROM alpine

RUN addgroup -S ks && adduser -S ks -G ks
USER ks
WORKDIR /home/ks/

COPY --from=builder /work/build/kontroller /usr/bin/kontroller

ARG image_version
ENV RELEASE=$image_version

ENTRYPOINT ["kontroller"]
