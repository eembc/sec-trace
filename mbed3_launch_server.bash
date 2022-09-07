#!/usr/bin/env bash
# Copyright (c) 2022 EEMBC
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

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
        force_ciphersuite=TLS1-3-AES-128-CCM-SHA256 \
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
