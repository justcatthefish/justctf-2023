FROM python:3.11

RUN pip install pwntools
RUN apt update -y && apt install -y tcpdump

WORKDIR /workdir
COPY ./client/ .
COPY ./gen_pcap/client.sh .
RUN chmod +x ./client.sh

ENV PWNLIB_NOTERM 1

ARG HOST
ARG PORT
ARG FLAG
ARG TCPDUMP_OUTFILE

ENV ENV_HOST ${HOST}
ENV ENV_PORT ${PORT}
ENV ENV_FLAG ${FLAG}
ENV ENV_TCPDUMP_OUTFILE ${TCPDUMP_OUTFILE}

CMD ./client.sh
