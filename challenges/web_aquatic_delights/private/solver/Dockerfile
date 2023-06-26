FROM python:3.10-slim

COPY ./solver.py /
COPY ./requests-racer-master.tar /

RUN chmod 755 /solver.py
RUN tar -xvf /requests-racer-master.tar
RUN python setup.py install

ENTRYPOINT ["/solver.py"]