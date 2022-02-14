#!/usr/bin/env bash
set -ex

# export ITAG=latest
export WTAG=test

# dep ensure
CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o k8s-ca-websocket .
chmod +x k8s-ca-websocket
 
docker build --no-cache -f Dockerfile.test -t quay.io/armosec/k8s-ca-websocket-ubi:$WTAG .
rm -rf k8s-ca-websocket
# docker push quay.io/armosec/k8s-ca-websocket-ubi:$WTAG
 

kubectl -n armo-system patch  deployment armo-web-socket -p '{"spec": {"template": {"spec": { "containers": [{"name": "armo-web-socket", "imagePullPolicy": "Never"}]}}}}' || true
kubectl -n armo-system set image deployment/armo-web-socket armo-web-socket=quay.io/armosec/k8s-ca-websocket-ubi:$WTAG || true
kubectl delete pod -n armo-system $(kubectl get pod -n armo-system | grep web-socket |  awk '{print $1}')
kubectl logs -f -n armo-system $(kubectl get pod -n armo-system | grep web-socket |  awk '{print $1}')
