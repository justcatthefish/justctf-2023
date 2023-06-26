FROM ghcr.io/cross-rs/armv7-unknown-linux-gnueabihf:latest
ENV CROSS_CONTAINER_IN_CONTAINER=true

RUN dpkg --add-architecture armv7 && \
    apt-get remove docker docker-engine docker.io containerd runc \
    && apt-get update \
    && apt-get install -y \
    curl \
    gcc \
    && curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal --default-toolchain stable \
    && export CARGO_HOME=$HOME/.cargo \
    && export PATH=$PATH:$CARGO_HOME/bin \
    && rustup target add armv7-unknown-linux-gnueabihf \
    && apt-get install -y apt-transport-https ca-certificates curl gnupg-agent software-properties-common \
    && curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg \
    && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null \
    && apt-get update \
    && apt-get install -y docker-ce docker-ce-cli containerd.io

WORKDIR /usr/src/rustberry
COPY ./src .

VOLUME /output

RUN export CARGO_HOME=$HOME/.cargo \
    && export PATH=$PATH:$CARGO_HOME/bin \
    && cargo install cross

RUN /bin/bash