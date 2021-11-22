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