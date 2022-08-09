#!/usr/bin/env bash

WOLF_SERVER_DIR=~/github/wolfssl/wolfssl/examples/server
CERT_DIR=/home/ptorelli/github/eembc/sec-trace/mycerts

cd $WOLF_SERVER_DIR

mode=$1

case $mode in
high)
	# Note: '-E' option is EEMBC custom
	./server \
		-v 4 \
		-p 11111 \
		-l TLS_AES_256_GCM_SHA384 \
		-E \
		-A $CERT_DIR/high/ca.crt \
		-c $CERT_DIR/high/server.crt \
		-k $CERT_DIR/high/server.key;;
medium)
	# -Y forces SECP256R1
	./server \
		-v 4 \
		-p 11111 \
		-l TLS_AES_128_CCM_SHA256 \
		-Y \
		-A $CERT_DIR/medium/ca.crt \
		-c $CERT_DIR/medium/server.crt \
		-k $CERT_DIR/medium/server.key;;
light)
	# -t forces X25519
	./server \
		-v 4 \
		-p 11111 \
		-l TLS_CHACHA20_POLY1305_SHA256 \
		-t \
		-A $CERT_DIR/light/ca.crt \
		-c $CERT_DIR/light/server.crt \
		-k $CERT_DIR/light/server.key;;
*)
	echo "Mode '$mode' is not valid; must be light, medium, high"
	exit -1
esac
