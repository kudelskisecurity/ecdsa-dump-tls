#!/usr/bin/env bash

openssl ecparam -out private.pem -name prime256v1 -genkey
openssl ec -in private.pem -outform der -out private.der
openssl req -new -key private.pem -x509 -nodes -days 365 -out cert.pem -subj "/C=US/ST=CA/L=SF/O=KS/CN=localhost"