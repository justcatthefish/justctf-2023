#!/bin/sh

# No spaces here
NAME="aquatic_delights"

# Build task docker image and run it
cd private
docker build -t aquatic_delights .
docker compose up -d
