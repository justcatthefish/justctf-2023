#!/bin/bash

tcpdump -i eth0 -w $ENV_TCPDUMP_OUTFILE &
PID=$!
echo "tcpdump pid: ${PID}"

./worker

sleep 5
kill $PID
wait
