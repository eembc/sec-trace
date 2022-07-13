#!/usr/bin/env bash

# note this isn't really light because we're not using Ed25519
#	named_groups=secp256r1 \
#	key_exchange_modes=ecdhe_ecdsa \

./ssl/ssl_server2 \
	force_ciphersuite=TLS1-3-AES-128-CCM-SHA256 \
	force_version=tls13 \
	curves=secp256r1 \
	tickets=0 \
	auth_mode=required \
	crt_file=./certs/server.crt \
	key_file=./certs/server.key \
	ca_file=./certs/ca.crt

