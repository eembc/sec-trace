#!/usr/bin/env bash

MBED_SERVER_DIR=~/github/Mbed-TLS/mbedtls/build/programs/ssl
CERT_DIR=/home/ptorelli/github/eembc/sec-trace/mycerts

cd $MBED_SERVER_DIR

mode=$1

case $mode in
high)
    ./ssl_server2 \
        server_port=11111 \
        force_version=tls13 \
        force_ciphersuite=TLS1-3-AES-256-GCM-SHA384 \
        curves=secp384r1 \
        ca_file=$CERT_DIR/high/ca.crt \
        crt_file=$CERT_DIR/high/server.crt \
        key_file=$CERT_DIR/high/server.key \
        tickets=0 \
        auth_mode=required
        ;;
medium)
    ./ssl_server2 \
        server_port=11111 \
        force_version=tls13 \
        force_ciphersuite=TLS1-3-AES-256-GCM-SHA384 \
        curves=secp256r1 \
        ca_file=$CERT_DIR/medium/ca.crt \
        crt_file=$CERT_DIR/medium/server.crt \
        key_file=$CERT_DIR/medium/server.key \
        tickets=0 \
        auth_mode=required
        ;;
light)
    echo "This is 'FAKE LIGHT' because we don't have 25519"
    ./ssl_server2 \
        debug_level=100 \
        server_port=11111 \
        force_version=tls13 \
        force_ciphersuite=TLS1-3-CHACHA20-POLY1305-SHA256 \
        curves=secp256r1 \
        ca_file=$CERT_DIR/medium/ca.crt \
        crt_file=$CERT_DIR/medium/server.crt \
        key_file=$CERT_DIR/medium/server.key \
        tickets=0 \
        auth_mode=required
        ;;
*)
	echo "Mode '$mode' is not valid; must be light, medium, high"
	exit -1
esac
