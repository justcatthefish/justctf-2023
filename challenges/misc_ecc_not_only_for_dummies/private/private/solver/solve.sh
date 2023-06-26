#!/usr/bin/env sh

if [ "$#" -lt 2 ]; then
   echo "Use: <host> <port>"
   exit 1
fi

docker build -t solver-misc-ecc-not-only-for-dummies .
docker run --rm -it \
   --security-opt=no-new-privileges --cap-drop=ALL --user 1000:1000 \
   --network=host \
   solver-misc-ecc-not-only-for-dummies \
   /solve.py HOST="$1" PORT="$2" $*