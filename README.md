# Websocket

The Websocket is an in-cluster component of the Kubescape security platform.
It allows clients to connect to itself, listens for commands from the connected clients and controls other in-cluster components according to received commands.


## API Documentation

The Websocket provides an HTTP API.
You can learn more about the API using one of the provided interactive OpenAPI UIs:
- SwaggerUI, available at `/openapi/v2/swaggerui`
- RapiDoc, available at `/openapi/v2/rapi`
- Redoc, available at `/openapi/v2/docs`

## Misc

add git submodules
```git submodule update --init --recursive```


### env variables

Checkout utils/environmentvariables.go

## Trigger action

```
curl -X POST http://<websocket-url>/v1/triggerAction
   -H 'Content-Type: application/json'
   -d '{"commands":[{"CommandName": "scan", "WildWlid": "wlid://cluster-minikube-v1"}]}'
```

### Trigger Kubescape scan

```
curl -X POST \
   -H 'Content-Type: application/json' \
   -d '{"commands":[{"CommandName":"kubescapeScan","args":{"scanV1": {"submit": true}}}]}' \
   http://127.0.0.1:4002/v1/triggerAction
```

### Set kubescape cronJob Kubescape scan

```
curl -X POST \
   -H 'Content-Type: application/json' \
   -d '{"commands":[{"CommandName":"setKubescapeCronJob","args":{"kubescapeJobParams":{"cronTabSchedule": "* * * * *"},"scanV1": {"submit": true}}}]}' \
   http://127.0.0.1:4002/v1/triggerAction
```

curl -X POST \
   -H 'Content-Type: application/json' \
   -d '{"commands":[{"CommandName":"setKubescapeCronJob","args":{"kubescapeJobParams":{"cronTabSchedule": "* * * * *"},"scanV1": {"submit": true, "targetType": "framework", "targetNames": ["nsa"]}}}]}' \
   http://127.0.0.1:4002/v1/triggerAction
### Trigger image scan

```
curl -X POST http://127.0.0.1:4002/v1/triggerAction -H 'Content-Type: application/json' -d '{"commands":[{"CommandName": "scan", "WildWlid": "wlid://cluster-minikube-v1"}]}'
```
   
### Set vuln-scan 
```
curl -X POST \
   -H 'Content-Type: application/json' \
   -d '{
         "commands": [
            {
                  "CommandName": "setVulnScanCronJob",
                  "WildWlid": "wlid://cluster-minikube/namespace-systest-ns-chj8",
                  "args": {
                     "jobParams": {
                        "cronTabSchedule": "* * * * *"
                     }
                  }
            }
         ]
      }' \
   http://127.0.0.1:4002/v1/triggerAction
```

### Update vuln-scan 
```
curl -X POST \
   -H 'Content-Type: application/json' \
   -d '{
         "commands": [
            {
                  "CommandName": "updateVulnScanCronJob",
                  "args": {
                     "jobParams": {
                        "cronTabSchedule": "* * * * *",
                        "name": "vuln-scan-scheduled-2393196145723502557"
                     }
                  }
            }
         ]
      }' \
   http://127.0.0.1:4002/v1/triggerAction
```

### Delete vuln-scan 
```
curl -X POST \
   -H 'Content-Type: application/json' \
   -d '{
         "commands": [
            {
                  "CommandName": "deleteVulnScanCronJob",
                  "args": {
                     "jobParams": {
                        "cronTabSchedule": "2 0 * * *",
                        "name": "vuln-scan-scheduled-605400646375517620"
                     }
                  }
            }
         ]
      }' \
   http://127.0.0.1:4002/v1/triggerAction
```
