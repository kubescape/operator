#!/usr/bin/env bash
set -ex

go get github.com/google/go-licenses
export GOPATH=`dirname "$PWD"`
export PACKAGE_NAME=`basename "$PWD"`
$GOROOT/bin/go-licenses save $PACKAGE_NAME  --save_path dist/licenses/

CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o k8s-ca-websocket .
chmod +x k8s-ca-websocket
docker build --no-cache -t dreg.eust0.cyberarmorsoft.com:443/k8s-ca-websocket:v1 -t dreg.eust0.cyberarmorsoft.com:443/k8s-ca-websocket:latest .


rm -rf k8s-ca-websocket

docker push dreg.eust0.cyberarmorsoft.com:443/k8s-ca-websocket
