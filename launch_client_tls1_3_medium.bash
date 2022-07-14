#!/usr/bin/env bash

./ssl/ssl_client2 \
	force_version=tls13 \
	force_ciphersuite=TLS1-3-AES-128-CCM-SHA256 \
	curves=secp256r1 \
	ca_file=./mycerts/medium/ca.crt \
	crt_file=./mycerts/medium/client.crt \
	key_file=./mycerts/medium/client.key \
	server_name=localhost \
	server_addr=127.0.0.1


