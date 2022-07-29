#!/usr/bin/env bash

BASE=`dirname $0`

$BASE/ssl/ssl_server2 \
	force_version=tls13 \
	force_ciphersuite=TLS1-3-AES-128-CCM-SHA256 \
	curves=secp256r1 \
	ca_file=$BASE/mycerts/medium/ca.crt \
	crt_file=$BASE/mycerts/medium/server.crt \
	key_file=$BASE/mycerts/medium/server.key \
	tickets=0 \
	auth_mode=required

