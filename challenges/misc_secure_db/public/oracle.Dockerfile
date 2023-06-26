FROM debian:bookworm-slim

RUN apt update

RUN apt-get update && apt-get install -y libsodium23 libgrpc++1.51 && rm -rf /var/lib/apt/lists/*

COPY bin/libpaseto.so /usr/lib/libpaseto.so
COPY test/private.key /task/private.key
COPY test/db /task/db

COPY bin/secure_db_task-runner /task/runner

WORKDIR /task
CMD ./runner