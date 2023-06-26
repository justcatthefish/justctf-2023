FROM python:3.10-slim

RUN pip install pwntools Flask pycryptodome crc

COPY ./solver.py /
RUN chmod 755 /solver.py

ENTRYPOINT ["/solver.py"]