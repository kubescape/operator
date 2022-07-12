#!/bin/bash

curl -X POST http://127.0.0.1:4002/v1/triggerAction -H 'Content-Type: application/json' -d @registryScanPayload.json -v -w "\\n"