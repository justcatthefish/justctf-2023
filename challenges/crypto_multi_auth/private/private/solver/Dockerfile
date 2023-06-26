FROM python:3.10

RUN apt-get update && apt-get install -y git libssl-dev libffi-dev build-essential
RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install --upgrade pwntools

COPY solve.py /solve.py