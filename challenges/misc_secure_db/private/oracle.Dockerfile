FROM debian:bookworm-slim

RUN apt update

RUN apt-get update && apt-get install -y libsodium23 libgrpc++1.51 && rm -rf /var/lib/apt/lists/*

COPY private/libs /usr/lib/
COPY private/private.key /task/private.key
COPY private/db /task/db

COPY private/secure_db_task-runner /task/runner

WORKDIR /task
CMD ./runner