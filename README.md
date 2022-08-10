# Kontroller 

The Kontroller is an in-cluster component of the Kubescape security platform.
It allows clients to connect to itself, listens for commands from the connected clients and controls other in-cluster components according to received commands.


## API Documentation

The Websocket provides an HTTP API.
You can learn more about the API using one of the provided interactive OpenAPI UIs:
- SwaggerUI, available at `/openapi/v2/swaggerui`
- RapiDoc, available at `/openapi/v2/rapi`
- Redoc, available at `/openapi/v2/docs`


## Environment Variables

Check out utils/environmentvariables.go

## Example Requests

### Trigger an Action

```
curl -X POST http://<websocket-url>/v1/triggerAction
   -H 'Content-Type: application/json'
   -d '{"commands":[{"CommandName": "scan", "WildWlid": "wlid://cluster-minikube-v1"}]}'
```

### Trigger a Kubescape Scan

```
curl -X POST \
   -H 'Content-Type: application/json' \
   -d '{"commands":[{"CommandName":"kubescapeScan","args":{"scanV1": {"submit": true}}}]}' \
   http://127.0.0.1:4002/v1/triggerAction
```

### Create a CronJob that Runs Kubescape Scans

```
curl -X POST \
   -H 'Content-Type: application/json' \
   -d '{"commands":[{"CommandName":"setKubescapeCronJob","args":{"kubescapeJobParams":{"cronTabSchedule": "* * * * *"},"scanV1": {"submit": true}}}]}' \
   http://127.0.0.1:4002/v1/triggerAction
```

```
curl -X POST \
   -H 'Content-Type: application/json' \
   -d '{"commands":[{"CommandName":"setKubescapeCronJob","args":{"kubescapeJobParams":{"cronTabSchedule": "* * * * *"},"scanV1": {"submit": true, "targetType": "framework", "targetNames": ["nsa"]}}}]}' \
   http://127.0.0.1:4002/v1/triggerAction
```

### Trigger an Image Scan

```
curl -X POST http://127.0.0.1:4002/v1/triggerAction -H 'Content-Type: application/json' -d '{"commands":[{"CommandName": "scan", "WildWlid": "wlid://cluster-minikube-v1"}]}'
```
   
### Create a CronJob that runs Vulnerability Scans

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

### Update a CronJob that runs Vulnerability Scans

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

### Delete a CronJob that runs Vulnerability Scans

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
