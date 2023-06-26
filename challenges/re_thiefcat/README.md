### thiefcat
My friend told me they made a terminal based game, but using some issue with stock netcat as an excuse they sent me this netcat-like binary telling me to use it instead! I didn't get the source code, but I took a quick look at it using a well-known state-of-the-art reverse engineering tool and it seemed perfectly safe to run. However, it stole the flag for this task from me! Can you get it back?

I recorded the network traffic and reconstructed a simple server in Python from it. The program was confirmed to run in a ubuntu:20.04 container, but it should run on almost any Linux distro out there.


Attachments:
* [thiefcat_server.py](./public/thiefcat_server.py)
* [thiefcat](./public/thiefcat)