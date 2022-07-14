#!/usr/bin/env bash

./ssl/ssl_client2 \
	force_version=tls13 \
	force_ciphersuite=TLS1-3-AES-256-GCM-SHA384 \
	curves=secp384r1 \
	ca_file=./mycerts/high/ca.crt \
	crt_file=./mycerts/high/client.crt \
	key_file=./mycerts/high/client.key \
	server_name=localhost \
	server_addr=127.0.0.1


