#!/usr/bin/env bash
set -ex

export ITAG=latest
export WTAG=test

# dep ensure
CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o k8s-ca-websocket .
chmod +x k8s-ca-websocket
 
docker build --no-cache -f Dockerfile.test -t quay.io/armosec/k8s-ca-websocket-ubi:$WTAG .
rm -rf k8s-ca-websocket
docker push quay.io/armosec/k8s-ca-websocket-ubi:$WTAG
 

# kubectl -n cyberarmor-system patch  deployment ca-websocket -p '{"spec": {"template": {"spec": { "containers": [{"name": "ca-websocket", "imagePullPolicy": "Never"}]}}}}' || true
kubectl -n cyberarmor-system set image deployment/ca-websocket ca-websocket=quay.io/armosec/k8s-ca-websocket-ubi:$WTAG || true
kubectl delete pod -n cyberarmor-system $(kubectl get pod -n cyberarmor-system | grep websocket |  awk '{print $1}')
kubectl logs -f -n cyberarmor-system $(kubectl get pod -n cyberarmor-system | grep websocket |  awk '{print $1}')
