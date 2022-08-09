# THIS IS FAKE LIGHT BECAUSE WE DON'T HAVE 25519
# Note: must be built with
# -g for debug info
# -fcf-protection=none ; early GCC can't access state prologue
# i.e.:
# 	% export CFLAGS="-g -O0 -fcf-protection=none"
#   % cmake .. -DENABLE_TESTING=OFF

set pagination off

set args \
	force_version=tls13 \
	force_ciphersuite=TLS1-3-CHACHA20-POLY1305-SHA256 \
	curves=secp256r1 \
	ca_file=$PWD/mycerts/medium/ca.crt \
	crt_file=$PWD/mycerts/medium/client.crt \
	key_file=$PWD/mycerts/medium/client.key \
	server_name=localhost \
	server_addr=127.0.0.1 \
	server_port=11111

# Prevent the application output from mixing with backtrace!
tty /dev/null

# This prints the client state about to be executed
# Note: the parser only expects one "print" command.
rbreak mbedtls_ssl_tls13_handshake_client_step
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
