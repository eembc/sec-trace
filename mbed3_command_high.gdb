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

# Note: must be built with
# -g for debug info
# -fcf-protection=none ; early GCC can't access state prologue

set pagination off

set args \
	force_version=tls13 \
	force_ciphersuite=TLS1-3-AES-256-GCM-SHA384 \
	curves=secp384r1 \
	ca_file=$PWD/mycerts/high/ca.crt \
	crt_file=$PWD/mycerts/high/client.crt \
	key_file=$PWD/mycerts/high/client.key \
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
