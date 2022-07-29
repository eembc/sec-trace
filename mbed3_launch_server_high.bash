#!/usr/bin/env bash

BASE=`dirname $0`

$BASE/ssl/ssl_server2 \
    debug_level=100 \
	force_version=tls13 \
	force_ciphersuite=TLS1-3-AES-256-GCM-SHA384 \
	curves=secp384r1 \
	ca_file=$BASE/mycerts/high/ca.crt \
	crt_file=$BASE/mycerts/high/server.crt \
	key_file=$BASE/mycerts/high/server.key \
	tickets=0 \
	auth_mode=required
