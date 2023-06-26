#!/bin/bash

if [ "$#" -lt 2 ]; then
    echo "Use: <host> <port>"
    exit 1
fi

HOST=$1
PORT=$2

cd private/solver
./solve.sh $HOST $PORT
cd -