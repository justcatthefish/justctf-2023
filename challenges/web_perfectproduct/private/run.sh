#!/bin/sh

# Port to which the task will be exposed
PORT=${1-1337}

# No spaces here
NAME="web-perfect-product"

cd public
export MAX_CORES=50

docker build -t ${NAME} -f Dockerfile .

cd ../private

docker compose -p manager -f docker-compose.yml rm -f --stop
docker compose -p manager -f docker-compose.yml build
docker compose -p manager -f docker-compose.yml up -d

#docker rm -f ${NAME}
#docker run -d \
#    --restart=always \
#    --name=${NAME} \
#    -p $PORT:80 \
#    ${NAME}
