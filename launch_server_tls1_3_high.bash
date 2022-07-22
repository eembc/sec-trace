#!/usr/bin/env bash

./ssl/ssl_server2 \
    debug_level=100 \
	force_version=tls13 \
	force_ciphersuite=TLS1-3-AES-256-GCM-SHA384 \
	curves=secp384r1 \
	ca_file=./mycerts/high/ca.crt \
	crt_file=./mycerts/high/server.crt \
	key_file=./mycerts/high/server.key \
	tickets=0 \
	auth_mode=required

