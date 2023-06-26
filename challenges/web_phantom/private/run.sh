#!/usr/bin/env bash

NAME="phantom"

# cd src
# docker build -t ${NAME} .
# docker run -d \
#     --restart=always \
#     --name=${NAME} \
#     --env-file=.env \
#     -p 80:8000 \
#     ${NAME}

docker-compose -p web_phantom -f docker-compose.yml rm --force --stop
docker-compose -p web_phantom -f docker-compose.yml build
docker-compose -p web_phantom -f docker-compose.yml up -d
