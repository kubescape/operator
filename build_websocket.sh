#!/usr/bin/env bash
set -ex

CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o k8s-ca-websocket .
chmod +x k8s-ca-websocket
docker build --no-cache -t dreg.eust0.cyberarmorsoft.com:443/k8s-ca-websocket-t:7  -t dreg.eust0.cyberarmorsoft.com:443/k8s-ca-websocket:latest .


rm -rf k8s-ca-websocket

docker push dreg.eust0.cyberarmorsoft.com:443/k8s-ca-websocket-t:7 dreg.eust0.cyberarmorsoft.com:443/k8s-ca-websocket:latest
