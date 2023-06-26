#!/usr/bin/env bash

docker-compose -p web_css -f private/docker-compose.yml rm --force --stop
docker-compose -p web_css -f private/docker-compose.yml build
docker-compose -p web_css -f private/docker-compose.yml up
