#!/bin/sh

# Port to which the task will be exposed
PORT_WEB=${1-5000}
PORT_SMTP=${2-8025}

# No spaces here
NAME="web-essamtp"

# Build task docker image
cd private
docker build -t ${NAME} -f Dockerfile .

docker rm -f ${NAME}
docker run -d \
    --restart=always \
    --name=${NAME} \
    --env-file=.env \
    -p $PORT_WEB:5000 \
    -p $PORT_SMTP:8025 \
    ${NAME}
