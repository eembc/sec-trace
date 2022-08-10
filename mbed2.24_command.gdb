# Note: must be built with
# -g for debug info
# -fcf-protection=none ; early GCC can't access state prologue

set pagination off

set args server_name=localhost \
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

# Prevent the application output from mixing with backtrace!
tty /dev/null

# This prints the client state about to be executed
# Note: the parser only expects one "print" command.
rbreak mbedtls_ssl_handshake_client_step
command
silent
print ssl->state
continue
end

rbreak mbedtls_.*aes
command
silent
backtrace
continue 
end

rbreak mbedtls_ccm
command
silent
backtrace
continue 
end

rbreak mbedtls_ecdh
command
silent
backtrace
continue 
end

rbreak mbedtls_ecdsa
command
silent
backtrace
continue 
end

rbreak mbedtls_gcm
command
silent
backtrace
continue 
end

rbreak mbedtls_sha
command
silent
backtrace
continue 
end

rbreak mbedtls_chacha
command
silent
backtrace
continue 
end

run
quit
