#!/bin/bash
	# https://ppamo-poc-cloudant-access.herokuapp.com/phishing/credentials

curl --header 'Content-type: application/json' \
	"http://localhost:8089/phishing/credentials?u=pablo&k=asdasdasd&s=facebook&ak=123456"

echo
