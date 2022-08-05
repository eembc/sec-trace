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

rbreak wc_ChaCha20Poly1305.*
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
