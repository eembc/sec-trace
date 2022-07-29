set pagination off

set args \
    -v 4 \
    -p 4433 \
    -A /home/ptorelli/github/eembc/sec-trace/mycerts/medium/ca.crt \
    -c /home/ptorelli/github/eembc/sec-trace/mycerts/medium/client.crt \
    -k /home/ptorelli/github/eembc/sec-trace/mycerts/medium/client.key 

# Prevent the application output from mixing with backtrace!
tty /dev/null

break main
run



# This prints the client state about to be executed
# Note: the parser only expects one "print" command.
rbreak DoTls13HandShakeMsgType
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
