# Note: must be built with
# -g for debug info
# -fcf-protection=none ; early GCC can't access state prologue
# i.e.:
# 	% export CFLAGS="-g -O0 -fcf-protection=none"
#   % cmake .. -DENABLE_TESTING=OFF

set pagination off

set args \
	force_ciphersuite=TLS1-3-AES-128-CCM-SHA256 \
	force_version=tls13 \
	curves=secp256r1 \
	tickets=0 \
	auth_mode=required \
	crt_file=./certs/server.crt \
	key_file=./certs/server.key \
	ca_file=./certs/ca.crt

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
