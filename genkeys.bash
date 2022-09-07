#/usr/bin/env bash
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

CERTDIR=mycerts

mkdir -p $CERTDIR
pushd $CERTDIR

echo "extendedKeyUsage = serverAuth, clientAuth, codeSigning, emailProtection" > v3.ext
echo "basicConstraints = CA:FALSE" >> v3.ext
echo "keyUsage = nonRepudiation, digitalSignature, keyEncipherment" >> v3.ext

## Light: EdDSA + SHA256

mkdir light
pushd light

openssl genpkey -out ca.key -algorithm ed25519
openssl req -x509 -nodes -key ca.key -days 3650 -subj '/CN=CA' \
    -sha256 -out ca.crt 

openssl genpkey -out client.key -algorithm ed25519
openssl req -new -key client.key -out client.csr -subj '/CN=localhost'
openssl x509 -req -CA ca.crt -CAkey ca.key -CAcreateserial \
    -sha256 -in client.csr -out client.crt -days 3650 -extfile ../v3.ext

openssl genpkey -out server.key -algorithm ed25519
openssl req -new -key server.key -out server.csr -subj '/CN=localhost'
openssl x509 -req -CA ca.crt -CAkey ca.key -CAcreateserial \
    -sha256 -in server.csr -out server.crt -days 3650

popd

## Medium: ECDSA p256 + SHA256

mkdir medium
pushd medium

openssl ecparam -out ca.key -genkey -name prime256v1
openssl req -x509 -nodes -key ca.key -days 3650 -subj '/CN=CA' \
    -sha256 -out ca.crt 

openssl ecparam -out client.key -genkey -name prime256v1
openssl req -new -key client.key -out client.csr -subj '/CN=localhost'
openssl x509 -req -CA ca.crt -CAkey ca.key -CAcreateserial \
    -sha256 -in client.csr -out client.crt -days 3650 -extfile ../v3.ext

openssl ecparam -out server.key -genkey -name prime256v1
openssl req -new -key server.key -out server.csr -subj '/CN=localhost'
openssl x509 -req -CA ca.crt -CAkey ca.key -CAcreateserial \
    -sha256 -in server.csr -out server.crt -days 3650

popd

## High: ECDSA p384 + SHA384

mkdir high
pushd high

# Note that the subject CN for the server and client MUST be `localhost`.

openssl ecparam -out ca.key -genkey -name secp384r1
openssl req -x509 -nodes -key ca.key -days 3650 -subj '/CN=CA' \
    -sha384 -out ca.crt 

openssl ecparam -out client.key -genkey -name secp384r1
openssl req -new -key client.key -out client.csr -subj '/CN=localhost'
openssl x509 -req -CA ca.crt -CAkey ca.key -CAcreateserial \
    -sha384 -in client.csr -out client.crt -days 3650 -extfile ../v3.ext

openssl ecparam -out server.key -genkey -name secp384r1
openssl req -new -key server.key -out server.csr -subj '/CN=localhost'
openssl x509 -req -CA ca.crt -CAkey ca.key -CAcreateserial \
    -sha384 -in server.csr -out server.crt -days 3650

popd
popd
