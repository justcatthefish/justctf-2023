#!/usr/bin/env sh

if [ "$#" -le 1 ]; then
    echo "Use: <host> <port>"
    exit 1
fi

NAME="solver-pwn-mystery-locker"
cp ../mystery_locker ./mystery_locker
cp ../libc.so.6 ./libc.so.6
docker build -t ${NAME} .
docker run --rm -it \
    --security-opt=no-new-privileges --cap-drop=ALL --user 1000:1000 \
    --network=host \
    ${NAME} \
    /solve.py "HOST=$1" "PORT=$2" REMOTE 
