#!/usr/bin/env bash
set -ex

export ITAG=latest
export WTAG=test

# dep ensure
CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o k8s-ca-websocket .
chmod +x k8s-ca-websocket

# base image
docker build --no-cache -f Dockerfile.base -t dreg.eust0.cyberarmorsoft.com:443/k8s-base-image:$ITAG .
# docker push dreg.eust0.cyberarmorsoft.com:443/k8s-base-image:$ITAG

docker build --no-cache -f Dockerfile.test -t dreg.eust0.cyberarmorsoft.com:443/k8s-ca-websocket:$WTAG .
rm -rf k8s-ca-websocket
# docker push dreg.eust0.cyberarmorsoft.com:443/k8s-ca-websocket:$WTAG
 

kubectl -n cyberarmor-system patch  deployment ca-websocket -p '{"spec": {"template": {"spec": { "containers": [{"name": "ca-websocket-container", "imagePullPolicy": "Never"}]}}}}' || true
kubectl -n cyberarmor-system set image deployment/ca-websocket ca-websocket-container=dreg.eust0.cyberarmorsoft.com:443/k8s-ca-websocket:$WTAG || true
kubectl delete pod -n cyberarmor-system $(kubectl get pod -n cyberarmor-system | grep websocket |  awk '{print $1}')
kubectl logs -f -n cyberarmor-system $(kubectl get pod -n cyberarmor-system | grep websocket |  awk '{print $1}')