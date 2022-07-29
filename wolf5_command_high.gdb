set pagination off

set args \
    -v 4 \
    -p 4433 \
    -A $PWD/mycerts/high/ca.crt \
    -c $PWD/mycerts/high/client.crt \
    -k $PWD/mycerts/high/client.key 

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
