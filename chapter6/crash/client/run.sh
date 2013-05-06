#!/bin/sh

if [ -z "${PASSWORD}" ]; then
        echo "No password supplied (please supply via the PASSWORD env var"
        exit
fi

for i in $(seq 1 100)
do
        go run client.go -p "${PASSWORD}" -a 127.0.0.1:4141
done
