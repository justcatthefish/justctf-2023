#!/bin/sh

docker-compose -p web_safeblog -f docker/docker-compose.yml rm --force --stop
docker-compose -p web_safeblog -f docker/docker-compose.yml build
docker-compose -p web_safeblog -f docker/docker-compose.yml up
