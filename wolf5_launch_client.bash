#!/usr/bin/env bash

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
#		-A $CERT_DIR/$mode/ca.crt \
#		-c $CERT_DIR/$mode/client.crt \
#		-k $CERT_DIR/$mode/client.key;;
    ;;
*)
	echo "Mode '$mode' is not valid; must be light, medium, high"
	exit -1
esac
