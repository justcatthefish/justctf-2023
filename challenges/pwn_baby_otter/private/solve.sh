#!/bin/sh

if [ "$#" -le 1 ]; then
    echo "Use: <host> <port>"
    exit 1
fi

HOST=$1
PORT=$2

cd private/
HOST=$HOST PORT=$PORT ./run_client.sh
