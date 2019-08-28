#!/usr/bin/env bash

CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o cawebsocket .
chmod +x cawebsocket
docker build --no-cache -t dreg.eust0.cyberarmorsoft.com:443/k8s-ca-websocket .
docker build --no-cache -t dreg.eust0.cyberarmorsoft.com:443/k8s-ca-websocket:v6 .

rm -rf cawebsocket

docker push dreg.eust0.cyberarmorsoft.com:443/k8s-ca-websocket
