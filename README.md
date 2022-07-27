# Introduction

This repo contains tools for profiling the cryptographic compute load for
a TLS handshake using mbedTLS 3.2.x. We use three different crypto strengths:

* High:  TLS1-3-AES-256-GCM-SHA384 on curve secp384r1
* Medium:  TLS1-3-AES-128-CCM-SHA256 on curve secp256r1
* Light: ChaChaPoly1305, SHA256, Ed25591, X25519 (latter two unsupported by mbedTLS)

# Building the Tools

## mbedTLS 3.x Configuration

First clone mbedTLS:

```bash
% git clone git@github.com:Mbed-TLS/mbedtls
```

Then prepare a make area:

```bash
% mkdir build
% cd build
% cmake .. -DENABLE_TESTING=OFF
```

Now source one of the `config_(high|medium).src` files followed by `config_extra.src`.

```Bash
% source **path to sec-trace repo**/config_medium.src
% source **path to sec-trace repo**/config_extra.src
```

## Notes on configuration

Questions: Should we configure for CTR or HMAC DRBG? (We have a choice)

Note: For some reason both secp256r1 and secp384r1 curves are requried which
causes a failure if secp384r1 is not included, even if it is not used.

Warning-errors: required to set MBEDTLS_CCM_C or MBEDTLS_GCM_C for a PSA
function that had an unused variable.

Warning-errors: required to set MBEDTLS_SSL_PROTO_TLS1_2 because of an unused
`ret` in `ssl_handle_hs_message_post_handshake`.

## Compilation

For tracing on x86 machines, we need to disable stack protection so that
GDB can skip the prologue and access the stack variables. GDB also needs
symbols and I prefer to run with zero optimizations. All three of these options
are specified in CFLAGS. Fortunately, the mbedTLS cmake script respects $CFLAGS.

From within the `mbedtls` repository:

```bash
% export CFLAGS="-g -O0 -fcf-protection=none"
% make
```

## Setup

After building mbedtls link the `build/program/ssl` folder to the repo. The
scripts call `ssl/ssl_client2` and `ssl/ssl_server2`.

From within this repository:

```bash
% cd **this repository**
% ln -s $MBEDTLSREPO/build/programs/ssl .
```

## Generating Keys

Keys and certs are already provided in `mycerts`.

The program openssl has no curve named secp256r1, just the Koblitz 'k'
variety; instead use prime256v1. secp384r1 does exist.

NOTE: That the subject CN for the server and client MUST be `localhost`.

See the script `genkeys.bash` for creating all the key and certificate material
for each level of strength.

## Collecting a Trace & Processing

From within the root of this repository:

```bash
% ./launch_server_tls1_3_medium.bash &
% gdb -command=command_medium.gdb ./ssl/ssl_client2 > log_medium.txt
% fg
% <ctrl-c>
% ./process_gdb_trace-mbed3.py log_medium.txt > table_medium.txt
```

To zoom in on the call stack for an alias, specify the alias number, e.g., 10:
```
% ./process_gdb_trace-mbed3.py log_medium.txt 10
```

# Results

The beginning of the report will indicate which `rbreak` functions are being
monitored and which are not. This is developer information. The script will
keep track of contexts as they are created and freed. Since the context is a
pointer to memory, it may be reused. Each time a context is used, it is given
a unique, increasing alias. If a context is freed without being initialized,
or if open contexts are left un-freed, a warning will be printed.

Example showing some functions that were caught in the `rbreak` regex, but are
not needed (`mbedtls_sha512_starts`), versus functions that are important, such
as `mbedtls_sha512_update`:

```
Hooked function 'mbedtls_sha512_init'
No hook for 'mbedtls_sha512_starts'
Hooked function 'mbedtls_sha512_update'
No hook for 'mbedtls_sha512'
No hook for 'mbedtls_sha512_finish'
Hooked function 'mbedtls_sha512_free'
Hooked function 'mbedtls_sha256_init'
No hook for 'mbedtls_sha256_starts'
Hooked function 'mbedtls_sha256_update'
No hook for 'mbedtls_sha256_finish'
Hooked function 'mbedtls_ecdh_init'
:
```

Next is a list of all mbed handshake states that are supported. The state
numbers are out of order, so this in order list helps keep track:

```
NOTE: Only these mbedTLS state codes are counted:
 .  0 MBEDTLS_SSL_HELLO_REQUEST
 .  1 MBEDTLS_SSL_CLIENT_HELLO
 .  2 MBEDTLS_SSL_SERVER_HELLO
 . 20 MBEDTLS_SSL_ENCRYPTED_EXTENSIONS
 .  5 MBEDTLS_SSL_CERTIFICATE_REQUEST
 .  3 MBEDTLS_SSL_SERVER_CERTIFICATE
 .  9 MBEDTLS_SSL_CERTIFICATE_VERIFY
 . 13 MBEDTLS_SSL_SERVER_FINISHED
 .  7 MBEDTLS_SSL_CLIENT_CERTIFICATE
 . 21 MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY
 . 11 MBEDTLS_SSL_CLIENT_FINISHED
 . 15 MBEDTLS_SSL_HANDSHAKE_WRAPUP
```

The columns of the table indicate the handshake state. The cells are the number
of bytes used by the primitive, or the number of occurances of sign/verify/DH.

The rows of the table are each alias, or, unique context. Furthermore, the same
context may be used for multiple tasks. When this occurs, a higher level
function that this call is nested in will be displayed to help sort things out.

For example:

```
00009,  sha256 (in mbedtls_ecp_gen_privkey_sw) ,  0x5555555d74a0
00009,  sha256 (in ecp_mul_comb_core)          ,  0x5555555d74a0
00009,  sha256 (in ecp_randomize_jac)          ,  0x5555555d74a0
00009,  sha256 (in ecp_mul_comb_after_precomp) ,  0x5555555d74a0
```

Here alias 9 is a sha256 that uses the same context memory pointer, but is
used for four different functions. Not shown is how many bytes are used and
which handshake stage the occur in (all are in 21: CLIENT_CERTIFICATE_VERIFY).

# Sample Data

The folder `data/` contains results collected on an Ubuntu 20 machine running
mbedTLS 3.2.1. The log contains the raw traces. The table are the final
results.
