FROM debian:bookworm-slim

RUN apt update && apt install -y python3 python3-pip && pip install pwntools --break-system-packages

COPY secure_db_task-solution /
COPY solve.py /
COPY cloud.key /
COPY 0_db /