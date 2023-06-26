#!/bin/sh

# Port to which the task will be exposed
PORT=${1-1337}

# No spaces here
NAME="misc-secure_db"

# Build task docker image
docker-compose -p misc_secure_db -f docker-compose.yml build
docker-compose -p misc_secure_db -f docker-compose.yml up -d
