#!/usr/bin/env sh
if [ -z "$1" ]
then
      echo "Usage: serve.sh PORT"
else
    socat TCP4-LISTEN:$1,reuseaddr,fork EXEC:"python formula.py"
fi

