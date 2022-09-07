#!/usr/bin/env bash
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

WOLF_CLIENT_DIR=~/github/wolfssl/wolfssl/examples/client
CERT_DIR=/home/ptorelli/github/eembc/sec-trace/mycerts
COMMAND_DIR=/home/ptorelli/github/eembc/sec-trace

mode=$1
LOG=log.wolf5.$mode
TABLE=table.wolf5.$mode

cd $WOLF_CLIENT_DIR

case $mode in
high|medium|light)
	gdb -command=$COMMAND_DIR/wolf5_command_$mode.gdb ./client > $LOG
    $COMMAND_DIR/process_gdb_trace_wolf5.py $LOG > $TABLE
    ;;
*)
	echo "Mode '$mode' is not valid; must be light, medium, high"
	exit -1
esac
