#!/usr/bin/env sh

docker build -t mango_solver .
docker run --rm -it -v $(pwd)/../../public/output.txt:/solver/output.txt mango_solver
