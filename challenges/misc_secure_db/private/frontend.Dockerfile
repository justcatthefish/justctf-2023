FROM python:3.9-slim

RUN apt-get update && apt-get install -y socat && rm -rf /var/lib/apt/lists/*

RUN mkdir /task

COPY private/generated /task/generated
COPY src/frontend/main.py /task/main.py

RUN pip install grpcio protobuf

CMD ["socat", "TCP-LISTEN:1337,fork", "exec:'python3 /task/main.py',pty"]
