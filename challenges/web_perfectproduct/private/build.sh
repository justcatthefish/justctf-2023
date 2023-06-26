#!/bin/sh

cp ../../autobuild/gen.py .
docker build -t build -f build.Dockerfile .
rm gen.py
docker run --rm -it build sh