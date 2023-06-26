FROM python:3.11
RUN pip install z3-solver pyshark pwntools
RUN apt update -y && DEBIAN_FRONTEND=noninteractive apt install -y tshark

COPY ./solver/ /tmp/
COPY ./gen_pcap/trace.pcap /tmp/
WORKDIR /tmp

CMD python ./solve.py

