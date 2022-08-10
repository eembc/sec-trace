# Purpose

This document captures some older methods that are helpful in case we need to
refer to the past.

# mbedTLS 2.6.0 and TLS 1.2, SecureMark-TLS version 1.0

The commands we used were:

```bash

% ./programs/ssl/ssl_server2 \
    debug_level=5 \
    server_addr=127.0.0.1 \
    force_version=tls1_2 \
    curves=secp256r1 \
    auth_mode=required \
    force_ciphersuite=TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256 \
    crt_file=./certs/server.crt \
    key_file=./certs/server.key \
    ca_file=./certs/ca.crt

% ./programs/ssl/ssl_client2 \
    debug_level=5 \
    server_name=localhost \
    server_addr=127.0.0.1 \
    force_version=tls1_2 \
    curves=secp256r1 \
    force_ciphersuite=TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256 \
    tickets=0 \
    ca_file=./certs/ca.crt \
    crt_file=./certs/client.crt \
    key_file=./certs/client.key

```

# mbedTLS 2.24.2 and TLS 1.3

```bash
./ssl/ssl_server2 \
        force_version=tls1_3 \
        force_ciphersuite=TLS_AES_128_CCM_SHA256 \
        key_exchange_modes=ecdhe_ecdsa \
        curves=secp256r1 \
        tickets=0 named_groups=secp256r1 \
        auth_mode=required \
        crt_file=./certs/server.crt \
        key_file=./certs/server.key \
        ca_file=./certs/ca.crt

./ssl/ssl_client2 \
        server_name=localhost \
        server_addr=127.0.0.1 \
        force_version=tls1_3 \
        force_ciphersuite=TLS_AES_128_CCM_SHA256 \
        key_exchange_modes=ecdhe_ecdsa \
        named_groups=secp256r1 \
        key_exchange_modes=ecdhe_ecdsa \
        curves=secp256r1 \
        ca_file=./certs/ca.crt \
        crt_file=./certs/client.crt \
        key_file=./certs/client.key
```
