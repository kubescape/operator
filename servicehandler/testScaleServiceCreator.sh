#!/bin/bash

for i in {1..100}; do
  kubectl expose deployment mysql --port=3306 --target-port=3306 --type=ClusterIP --name=mysql-service-${i}
done
