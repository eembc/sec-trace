# Note: must be built with
# -g for debug info
# -fcf-protection=none ; early GCC can't access state prologue

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

# To capture state changes a dummy command:
# void client_state_dummy(int state)
# needs to be added to the code so that we can break on it and fetch
# the parameter. Otherwise we need to fetch ssl->state ... which could
# be done, save it for TODO.
rbreak client_state_dummy
command
silent
backtrace
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
