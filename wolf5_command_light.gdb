# Note: You need to link `mycerts` into the client example area

# Note: must be built with
# -g for debug info
# -fcf-protection=none ; early GCC can't access state prologue
# i.e.:
# 	% export CFLAGS="-g -O0 -fcf-protection=none"
#   % cmake .. -DENABLE_TESTING=OFF

set pagination off

set args \
    -v 4 \
    -A $PWD/mycerts/light/ca.crt \
    -c $PWD/mycerts/light/client.crt \
    -k $PWD/mycerts/light/client.key 

# Prevent the application output from mixing with backtrace!
tty /dev/null

# Trigger dynamic libwolfssl library load
break main
run

# This prints the client state about to be executed
# Note: the parser only expects one "print" command.
# Use full regex to avoid @plt procedure linkage table
rbreak ^DoTls13HandShakeMsgType$
command
silent
backtrace
print type
continue
end

rbreak wc_curve25519.*
command
silent
backtrace
continue 
end

rbreak wc_ed25519.*
command
silent
backtrace
continue 
end

rbreak ^ChaCha20Poly1305_.*
command
silent
backtrace
continue 
end

rbreak wc_Aes.*
command
silent
backtrace
continue 
end


rbreak wc_InitSha.*
command
silent
backtrace
continue 
end

rbreak wc_Sha.*
command
silent
backtrace
continue 
end

rbreak wc_ecc_.*
command
silent
backtrace
continue 
end

c
quit
