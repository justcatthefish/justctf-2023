#!/bin/sh

NAME="pwn-tic-tac-toe-build"

mkdir binaries
docker build -f Dockerfile.build -t ${NAME} .
docker run --rm -it -v `pwd`:/host --cap-drop=ALL ${NAME} \
    bash -c "gcc -fPIC /host/src/rpc_server.c -o /host/binaries/rpc_server && gcc -shared -fPIC /host/src/rpc_tictactoe.c -o /host/binaries/rpc_tictactoe.so && python3 -c \"from pwn import *; context.arch='amd64';ELF.from_assembly(shellcraft.cat(b'/jailed/flag.txt') + shellcraft.exit(0)).save('/host/binaries/readflag')\""

chmod a+x ./binaries/readflag
