FROM golang:1.20-alpine as builder

ENV GO111MODULE=

ENV CGO_ENABLED=0

WORKDIR /work
ADD . .

RUN apk add git

WORKDIR /work
RUN go build -o build/operator

FROM alpine

RUN addgroup -S ks && adduser -S ks -G ks
USER ks
WORKDIR /home/ks/

COPY --from=builder /work/build/operator /usr/bin/operator

ARG image_version
ENV RELEASE=$image_version

ENTRYPOINT ["operator"]
