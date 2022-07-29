# Note: must be built with
# -g for debug info
# -fcf-protection=none ; early GCC can't access state prologue
# i.e.:
# 	% export CFLAGS="-g -O0 -fcf-protection=none"
#   % cmake .. -DENABLE_TESTING=OFF

set pagination off

set args \
	force_version=tls13 \
	force_ciphersuite=TLS1-3-AES-256-GCM-SHA384 \
	curves=secp384r1 \
	ca_file=$PWD/mycerts/high/ca.crt \
	crt_file=$PWD/mycerts/high/client.crt \
	key_file=$PWD/mycerts/high/client.key \
	server_name=localhost \
	server_addr=127.0.0.1

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
