#!/bin/sh

if [ "$#" -le 1 ]; then
    echo "Use: <host> <port>"
    exit 1
fi

HOST=$1
PORT=$2

(cat ./private/solution.txt; printf "\./readflag\n") | nc -vvv $HOST $PORT
