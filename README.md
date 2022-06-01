# Websocket
add git submodules
```git submodule update --init --recursive```


### env variables
CA_POSTURE_SCAN_SCHEDULE
CA_VULN_SCAN_SCHEDULE

[cronjob format](https://pkg.go.dev/github.com/robfig/cron)

## Supported Environments

| Environment |  value | default |
| :=== | :===:  | :===:  |
| `CA_SYSTEM_MODE` | `ALL`/`SCAN` | `ALL`  |


## Trigger action

```
curl -X POST http://<websocket-url>/v1/triggerAction
   -H 'Content-Type: application/json'
   -d '{"commands":[{"CommandName": "scan", "WildWlid": "wlid://cluster-dwertent-v1"}]}'
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
curl -X POST http://127.0.0.1:4002/v1/triggerAction -H 'Content-Type: application/json' -d '{"commands":[{"CommandName": "scan", "WildWlid": "wlid://cluster-dwertent-v1"}]}'
```
   
### Set vuln-scan 
```
curl -X POST \
   -H 'Content-Type: application/json' \
   -d '{
         "commands": [
            {
                  "CommandName": "setVulnScanCronJob",
                  "WildWlid": "wlid://cluster-minikube-moshe",
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
                        "cronTabSchedule": "2 0 * * *",
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