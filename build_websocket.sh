#!/usr/bin/env bash
set -ex

# export ITAG=latest
export WTAG=v0.0.1
# export CA_NAMESPACE=cyberarmor-system
# export CA_WS_NAME=ca-websocket

export CA_NAMESPACE=armo-system
export CA_WS_NAME=armo-web-socket

# dep ensure
CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o k8s-ca-websocket .
chmod +x k8s-ca-websocket

echo $(date -u) > ./build_date.txt

docker build --no-cache -f Dockerfile -t quay.io/armosec/k8s-ca-websocket-ubi:$WTAG .
rm -rf k8s-ca-websocket
# docker push quay.io/armosec/k8s-ca-websocket-ubi:$WTAG
 

kubectl -n $CA_NAMESPACE patch deployment $CA_WS_NAME -p '{"spec": {"template": {"spec": { "containers": [{"name": "'${CA_NAMESPACE}'", "imagePullPolicy": "Never"}]}}}}' || true
kubectl -n $CA_NAMESPACE set image deployment/$CA_WS_NAME $CA_WS_NAME=quay.io/armosec/k8s-ca-websocket-ubi:$WTAG || true
kubectl -n $CA_NAMESPACE delete pod $(kubectl -n $CA_NAMESPACE get pod | grep $CA_WS_NAME |  awk '{print $1}')
kubectl -n $CA_NAMESPACE logs -f $(kubectl -n $CA_NAMESPACE get pod | grep $CA_WS_NAME |  awk '{print $1}')
