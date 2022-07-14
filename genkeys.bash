#/usr/bin/env bash

CERTDIR=mycerts


mkdir -p $CERTDIR
pushd $CERTDIR

## Light: EdDSA + SHA256

mkdir light
pushd light

openssl genpkey -out ca.key -algorithm ed25519
openssl req -x509 -nodes -key ca.key -days 3650 -subj '/CN=CA' \
    -sha256 -out ca.crt 

openssl genpkey -out client.key -algorithm ed25519
openssl req -new -key client.key -out client.csr -subj '/CN=localhost'
openssl x509 -req -CA ca.crt -CAkey ca.key -CAcreateserial \
    -sha256 -in client.csr -out client.crt -days 3650

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
    -sha256 -in client.csr -out client.crt -days 3650

openssl ecparam -out server.key -genkey -name prime256v1
openssl req -new -key server.key -out server.csr -subj '/CN=localhost'
openssl x509 -req -CA ca.crt -CAkey ca.key -CAcreateserial \
    -sha256 -in server.csr -out server.crt -days 3650

popd

## High: ECDSA p384 + SHA384

mkdir high
pushd high

Note that the subject CN for the server and client MUST be `localhost`.

openssl ecparam -out ca.key -genkey -name secp384r1
openssl req -x509 -nodes -key ca.key -days 3650 -subj '/CN=CA' \
    -sha384 -out ca.crt 

openssl ecparam -out client.key -genkey -name secp384r1
openssl req -new -key client.key -out client.csr -subj '/CN=localhost'
openssl x509 -req -CA ca.crt -CAkey ca.key -CAcreateserial \
    -sha384 -in client.csr -out client.crt -days 3650

openssl ecparam -out server.key -genkey -name secp384r1
openssl req -new -key server.key -out server.csr -subj '/CN=localhost'
openssl x509 -req -CA ca.crt -CAkey ca.key -CAcreateserial \
    -sha384 -in server.csr -out server.crt -days 3650

popd
popd
