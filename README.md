
  
# Kontroller 

The Kontroller component is at the heart of the solution as it is the triggering engine for the different actions in the cluster; It responds to REST API requests and messages received over websocket connection, and triggers the relevant action in the cluster. Such actions could be triggering a configuration scan, image vulnerability scan, defining a recurring scan (by creating CronJobs), etc.

## Running Kontroller
Build Kontroller `go build .`  
Run the executable  
### Prerequisites
 * Running cluster
 * [Kubescape cluster components](https://github.com/armosec/armo-helm#installing-armo-cluster-components-in-a-kubernetes-cluster-using-helm)
### Preparations

After buliding Kontroller you need to prepare the environment for running.   
 * You need to open the ports of the other in-cluster components, to have access to them from the outside.

	```    
	kubectl port-forward -n armo-system service/armo-kubescape 8080:8080 & 
	kubectl port-forward -n armo-system service/armo-vuln-scan 8081:8080 & 
	kubectl port-forward -n armo-system service/armo-notification-service 8001:8001 &
	```

 * To configure Kontroller how to access to the other in-cluster components you need to define a configuration file (**clusterData**) with all the information inside, and add the file path to environment variable CONFIG.  
     `export CONFIG=path/to/clusterData.json`
   <details><summary>example/clusterData.json</summary>
   
   ```json5 
	{
       "gatewayWebsocketURL": "127.0.0.1:8001",
       "gatewayRestURL": "127.0.0.1:8002",
       "kubevulnURL": "127.0.0.1:8081",
       "kubescapeURL": "127.0.0.1:8080",
       "eventReceiverRestURL": "https://report.armo.cloud",
       "eventReceiverWebsocketURL": "wss://report.armo.cloud",
       "rootGatewayURL": "wss://ens.euprod1.cyberarmorsoft.com/v1/waitfornotification",
       "accountID": "*********************",
       "clusterName": "******", } 
	``` 
</details>


## API Documentation

The Kontroller provides an HTTP API.
You can learn more about the API using one of the provided interactive OpenAPI UIs:
- SwaggerUI, available at `/openapi/v2/swaggerui`
- RapiDoc, available at `/openapi/v2/rapi`
- Redoc, available at `/openapi/v2/docs`


## Environment Variables

Check out utils/environmentvariables.go

## Example Requests

<details><summary>Trigger an Action</summary>

```
curl -X POST http://<Kuntroller-url>/v1/triggerAction
   -H 'Content-Type: application/json'
   -d '{
	    "commands": [
		{
		    "CommandName": "scan",
		    "WildWlid": "wlid://cluster-minikube-v1"
		}
	    ]
	}'
```
</details>
<details><summary>Trigger a Kubescape Scan</summary>

```
curl -X POST \
   -H 'Content-Type: application/json' \
   -d '{
	    "commands": [
		{
		    "CommandName": "kubescapeScan",
		    "args": {
			"scanV1": {
			    "submit": true
			}
		    }
		}
	    ]
	}' \
   http://127.0.0.1:4002/v1/triggerAction
```
</details>
<details><summary>Create a CronJob that Runs Kubescape Scans</summary>

```
curl -X POST \
   -H 'Content-Type: application/json' \
   -d '{
	    "commands": [
		{
		    "CommandName": "setKubescapeCronJob",
		    "args": {
			"kubescapeJobParams": {
			    "cronTabSchedule": "* * * * *"
			},
			"scanV1": {
			    "submit": true
			}
		    }
		}
	    ]
	}' \
   http://127.0.0.1:4002/v1/triggerAction
```

```
curl -X POST \
   -H 'Content-Type: application/json' \
   -d '{
	    "commands": [
		{
		    "CommandName": "setKubescapeCronJob",
		    "args": {
			"kubescapeJobParams": {
			    "cronTabSchedule": "* * * * *"
			},
			"scanV1": {
			    "submit": true,
			    "targetType": "framework",
			    "targetNames": [
				"nsa"
			    ]
			}
		    }
		}
	    ]
	}' \
   http://127.0.0.1:4002/v1/triggerAction
```
</details>
<details><summary>Trigger an Image Scan</summary>

```
curl -X POST \
   -H 'Content-Type: application/json' \
   -d '{
	    "commands": [
		{
		    "CommandName": "scan",
		    "WildWlid": "wlid://cluster-minikube-v1"
		}
	    ]
	}' \
   http://127.0.0.1:4002/v1/triggerAction
```
</details>
<details><summary>Create a CronJob that runs Vulnerability Scans</summary>

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
</details>
<details><summary>Update a CronJob that runs Vulnerability Scans</summary>

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
</details>
<details><summary>Delete a CronJob that runs Vulnerability Scans</summary>

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
</details>  
	
## VS code configuration samples

You can use the samples files below to setup your VS code environment for building and debugging purposes.

<details><summary>.vscode/launch.json</summary>

```json5
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
We configure the Kontroller to listen to port 4002, and define the configuration in the clusterData.json file as mentioned above.
	</details>
And also need to open the ports of the other in-cluster components,  as mentioned above.

    
## Running Kontroller  as standalone

The Kontroller also supports running as a stand-alone.
For this you need to define in the config file, for the relevant values that will be empty
For example:
<details><summary>.vscode/clusterData.json</summary>

```json5
{
    "gatewayWebsocketURL": "",
    "gatewayRestURL": "",
    "kubevulnURL": "",
    "kubescapeURL": "",
    "eventReceiverRestURL": ",
    "eventReceiverWebsocketURL": "",
    "rootGatewayURL": "",
    "accountID": "*********************",
    "clusterName": "******"
}
```
</details>


