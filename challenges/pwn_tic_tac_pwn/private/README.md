## Info

Sources are in the `public` folder. Source code, binaries and dockerfile should all be given out to players.

## Building

gcc -fPIC -o rpc_server ../rpc_server.c
gcc -shared -fPIC -o rpc_tictactoe.so ../rpc_tictactoe.c

Run with the folder with rpc_rictactoe.so in the path.

## Testing

Test to check if the program works as intended:

LD_LIBRARY_PATH=. ./rpc_server < flag.txt

Payload to spawn a shell:

cat - solution.txt | LD_LIBRARY_PATH=. ./rpc_server