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

## Building Kontroller

Before running Kontroller we need to take care of communication between it and other components.
For example:
What is the address of the client that connects to it.
What is the address of the other in-cluster components that execute the commands.

### VS code configuration samples

You can use the samples files below to setup your VS code environment for building and debugging purposes.

<details><summary>.vscode/launch.json</summary>

```json5
// .vscode/launch.json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Launch Package",
            "type": "go",
            "request": "launch",
            "mode": "auto",
            "program":  "${workspaceRoot}",
                 "env": {
                     "PORT": "4002",
                     "NAMESPACE": "armo-system",
                     "CONFIG": "${workspaceRoot}/.vscode/clusterData.json",
            },
            "args": [
                "-alsologtostderr", "-v=4", "2>&1"
            ]
        }
    ]
}
```
   We configure the Kontroller to listen to port 4002, and define the configuration in the clusterData.json file as shown below.
</details>

<details><summary>.vscode/clusterData.json</summary>

```json5
// .vscode/clusterData.json
{
    "notificationWSURL": "127.0.0.1:8001",
    "vulnScanURL": "127.0.0.1:8081",
    "kubescapeURL": "127.0.0.1:8080",
    "eventReceiverREST": "",
    "customerGUID": "12345-12345-12345-12345",
    "clusterName": "minikube-v1"
}
```
</details>

Just need to open the ports of the other in-cluster components, to have access to them from the outside.

    kubectl port-forward -n armo-system service/armo-kubescape 8080:8080 & 
    kubectl port-forward -n armo-system service/armo-vuln-scan 8081:8080 & 
    kubectl port-forward -n armo-system service/armo-notification-service 8001:8001 &
    
#### Running Kontroller  as standalone

To run the Kontroller without connecting to other components, or to some of them, we will leave their value empty in the clusterData file.
For example:
<details><summary>.vscode/clusterData.json</summary>

```json5
// .vscode/clusterData.json
{
    "notificationWSURL": "",
    "vulnScanURL": "",
    "kubescapeURL": "",
    "eventReceiverREST": "",
    "customerGUID": "12345-12345-12345-12345",
    "clusterName": "minikube-v1"
}
```
</details>


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
