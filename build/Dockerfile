FROM golang:1.18-alpine as builder

ENV GO111MODULE=

ENV CGO_ENABLED=0

WORKDIR /work
ADD . .

RUN apk add git

WORKDIR /work
RUN go build -o build/trigger

FROM alpine

RUN addgroup -S armo && adduser -S armo -G armo
USER armo
WORKDIR /home/armo/

COPY --from=builder /work/build/trigger /usr/bin/trigger

ARG image_version
ENV RELEASE=$image_version

ENTRYPOINT ["trigger"]
