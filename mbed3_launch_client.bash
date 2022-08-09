#!/usr/bin/env bash

MBED_CLIENT_DIR=~/github/Mbed-TLS/mbedtls/build/programs/ssl
CERT_DIR=/home/ptorelli/github/eembc/sec-trace/mycerts
COMMAND_DIR=/home/ptorelli/github/eembc/sec-trace

mode=$1
LOG=$PWD/log.mbed3.$mode
TABLE=$PWD/table.mbed3.$mode

case $mode in
high|medium|light)
	gdb -command=$COMMAND_DIR/mbed3_command_$mode.gdb $MBED_CLIENT_DIR/ssl_client2 > $LOG
    $COMMAND_DIR/process_gdb_trace_mbed3.py $LOG > $TABLE
    ;;
*)
	echo "Mode '$mode' is not valid; must be light, medium, high"
	exit -1
esac
