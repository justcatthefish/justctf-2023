FROM debian:bookworm-slim

RUN apt update && apt install -y python3 python3-pip && pip install pwntools --break-system-packages

COPY pow.py /
COPY solve.py /
