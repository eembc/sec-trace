#!/usr/bin/env bash

./ssl/ssl_server2 \
	force_version=tls13 \
	force_ciphersuite=TLS1-3-AES-128-CCM-SHA256 \
	curves=secp256r1 \
	ca_file=./mycerts/medium/ca.crt \
	crt_file=./mycerts/medium/server.crt \
	key_file=./mycerts/medium/server.key \
	tickets=0 \
	auth_mode=required

