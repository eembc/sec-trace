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
#!/usr/bin/env bash

WOLF_SERVER_DIR=~/github/wolfssl/wolfssl/examples/server
CERT_DIR=/home/ptorelli/github/eembc/sec-trace/mycerts

cd $WOLF_SERVER_DIR

mode=$1

case $mode in
high)
	./server \
		-v 4 \
		-p 11111 \
		-l TLS_AES_256_GCM_SHA384 \
		--force-curve SECP384R1 \
		-A $CERT_DIR/high/ca.crt \
		-c $CERT_DIR/high/server.crt \
		-k $CERT_DIR/high/server.key;;
medium)
	./server \
		-v 4 \
		-p 11111 \
		-l TLS_AES_128_CCM_SHA256 \
		--force-curve SECP256R1 \
		-A $CERT_DIR/medium/ca.crt \
		-c $CERT_DIR/medium/server.crt \
		-k $CERT_DIR/medium/server.key;;
light)
	./server \
		-v 4 \
		-p 11111 \
		-l TLS_CHACHA20_POLY1305_SHA256 \
		--force-curve CURVE25519 \
		-A $CERT_DIR/light/ca.crt \
		-c $CERT_DIR/light/server.crt \
		-k $CERT_DIR/light/server.key;;
*)
	echo "Mode '$mode' is not valid; must be light, medium, high"
	exit -1
esac
