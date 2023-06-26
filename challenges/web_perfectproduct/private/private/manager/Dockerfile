FROM golang:1.19.6-buster as builder_manager
WORKDIR /code/
COPY . .
RUN go build -v ./cmd/manager/

FROM ubuntu:22.04
RUN apt-get update -y && apt-get install -y wget curl unzip

# install docker client only
ENV DOCKERVERSION=23.0.1
RUN curl -fsSLO https://download.docker.com/linux/static/stable/x86_64/docker-${DOCKERVERSION}.tgz \
  && tar xzvf docker-${DOCKERVERSION}.tgz --strip 1 -C /usr/local/bin docker/docker \
  && rm docker-${DOCKERVERSION}.tgz

WORKDIR /work
COPY --from=builder_manager /code/manager manager

USER root
CMD ["/work/manager"]
