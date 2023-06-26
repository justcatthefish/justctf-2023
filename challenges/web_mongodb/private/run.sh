#!/bin/sh

PORT=${1-1337}

# No spaces here
NAME="almost-finished"

# Build task docker image and run it
cd private
./build.sh
./run.sh
