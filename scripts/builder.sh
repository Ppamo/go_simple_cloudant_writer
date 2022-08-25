#!/bin/bash

IMAGE=golang:1.18

docker run -ti --rm --name builder \
	--volume $PWD:/go/src/ppamo/app \
	"$IMAGE" \
	sh -c "cd /go/src/ppamo/app && go get && CGO_ENABLED=0 GOOS=linux go build -v -a -o bin/server main.go"
