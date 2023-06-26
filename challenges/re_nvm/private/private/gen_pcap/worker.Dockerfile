FROM ubuntu:22.04

RUN apt update -y && apt install -y tcpdump

WORKDIR /workdir
COPY ./worker/worker .
COPY ./gen_pcap/worker.sh .
RUN chmod +x ./worker.sh ./worker

ARG TCPDUMP_OUTFILE
ENV ENV_TCPDUMP_OUTFILE ${TCPDUMP_OUTFILE}

CMD ./worker.sh
