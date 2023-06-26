FROM golang:1.20

RUN mkdir -p /solver
WORKDIR /solver
COPY go.mod solve.go /solver/

RUN go build

CMD ./solver
