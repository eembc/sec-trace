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

# Note: You need to link `mycerts` into the client example area

# Note: must be built with
# -g for debug info
# -fcf-protection=none ; early GCC can't access state prologue

set pagination off

set args \
    -v 4 \
    -A $PWD/mycerts/medium/ca.crt \
    -c $PWD/mycerts/medium/client.crt \
    -k $PWD/mycerts/medium/client.key 

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
