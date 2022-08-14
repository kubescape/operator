
# Kontroller 

The Kontroller component is at the heart of the solution as it is the triggering engine for the different actions in the cluster; It responds to REST API requests and messages received over websocket connection, and triggers the relevant action in the cluster. Such actions could be triggering a configuration scan, image vulnerability scan, defining a recurring scan (by creating CronJobs), etc.

## Running Kontroller
Build Kontroller `go build .`  
Run the executable, you can run the executable as a [stand alone](https://github.com/kubescape/kontroller#running-kontroller--as-standalone) and as part of the Kubescape cluster components.  
### Prerequisites
 * A running Kubernetes cluster
### Preparations
If you running the Kontroller as part of the Kubescape cluster components, you need to prepare the environment for running.  
As follows:  
 1. [install Kubescape cluster components](https://github.com/armosec/armo-helm#installing-armo-cluster-components-in-a-kubernetes-cluster-using-helm)
 2. Port-forward the other in-cluster components ports, this way the Kontroller will communicate with them.

	```    
	kubectl port-forward -n armo-system service/armo-kubescape 8080:8080 & 
	kubectl port-forward -n armo-system service/armo-vuln-scan 8081:8080 & 
	kubectl port-forward -n armo-system service/armo-notification-service 8001:8001 &
	```

 3. Add a configuration file.  
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
   
 4. Set the file path to the `CONFIG` environment variable 
     ```
     export CONFIG=path/to/clusterData.json
     ```
     
## API Documentation

The Kontroller provides an HTTP API.
You can learn more about the API using one of the provided interactive OpenAPI UIs:
- SwaggerUI, available at `/openapi/v2/swaggerui`
- RapiDoc, available at `/openapi/v2/rapi`
- Redoc, available at `/openapi/v2/docs`

## Environment Variables

Check out `utils/environmentvariables.go`

## Example Requests
#### Trigger an Action
<details><summary>Example</summary>

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

#### Trigger [Kubescape](https://github.com/armosec/kubescape) scanning
<details><summary>Example</summary>

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

#### Create a CronJob that will repeatedly trigger a Kubescape scanning all frameworks
<details><summary>Example</summary>

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
</details>

#### Create a CronJob that will repeatedly trigger a Kubescape scanning specific framework
<details><summary>Example</summary>

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

#### Trigger [Kubevuln](https://github.com/kubescape/kubevuln) scanning
<details><summary>Example</summary>

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

#### Create a CronJob that will repeatedly trigger a Kubevuln scanning
<details><summary>Example</summary>

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

#### Update a CronJob that repeatedly trigger a Kubevuln scanning
<details><summary>Example</summary>

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

#### Delete a CronJob that repeatedly trigger a Kubevuln scanning
<details><summary>Example</summary>

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
We configure the Kontroller to listen to port 4002, and define the configuration in the clusterData.json file [as mentioned above](https://github.com/kubescape/kontroller#preparations).
</details>

And also need to open the ports of the other in-cluster components, [as mentioned above](https://github.com/kubescape/kontroller#preparations).
    
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


