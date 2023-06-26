#!/bin/sh

if [ "$#" -le 1 ]; then
    echo "Use: <host> <port>"
    exit 1
fi

HOST=$1
PORT=$2

echo "NOTE: You will have to hit CTRL+C in this exploit for it to work. Okay? (press any key to continue)"
read x

cd private/solver
./solve.sh $HOST $PORT
