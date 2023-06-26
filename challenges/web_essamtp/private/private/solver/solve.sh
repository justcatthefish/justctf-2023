#!/usr/bin/env sh

if [ "$#" -le 3 ]; then
    echo "Use: <host> <smtp_port> <web_port> <solver_host>"
    exit 1
fi

NAME="solver-web-essamtp"
docker build -t ${NAME} .
docker run --rm -it \
    --security-opt=no-new-privileges --cap-drop=ALL --user 1000:1000 \
    -p 25:8825 \
    -p 2525:2525 \
    ${NAME} \
    python3 solve.py "HOST=$1" "PORT=$2" "WEB_PORT=$3" "SOLVER_HOST=$4"
