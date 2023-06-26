#pragma once

#include <sys/socket.h>
#include <arpa/inet.h>
#include <iostream>
#include <cstring>
#include <sys/time.h>
#include <unistd.h>


[[ noreturn ]]
void fail(const char *msg){
    std::cerr << msg << " failed" << std::endl;
    std::exit(1);
}

class Socket {
public:
    int listen_fd;
    int conn_fd;

    Socket() : listen_fd{-1}, conn_fd{-1} {
        if((listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0){
            fail("socket");
        }
        int enable = 1;
        if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&enable, sizeof(int)) != 0) {
            fail("setsockopt");
        }
    };

    ~Socket() {
        if(conn_fd != -1){
            shutdown(conn_fd, SHUT_RDWR);
            close(conn_fd);
        }
        if(listen_fd != -1){
            close(listen_fd);
        }
    };

    int start_listening(int port) {
        struct sockaddr_in serv_addr;
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        serv_addr.sin_port = htons(port);

        if(bind(listen_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) != 0){
            fail("bind");
        }

        if(listen(listen_fd, 1) != 0){
            fail("listen");
        }

        std::cout << "waiting for connection...\n";
        if((conn_fd = accept(listen_fd, (struct sockaddr*)NULL, NULL)) < 0) {
            fail("accept");
        }

        if(send("RDY") < 0){
            fail("ready");
        }

        std::cout << "client connected\n";
        return 0;
    }

    int send_n(const char* msg, uint32_t n) {
        return write(conn_fd, msg, n);
    }

    int send(const char* msg) {
        return send_n(msg, strlen(msg));
    }

    uint64_t get_time() {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        return (unsigned long long)(tv.tv_sec) * 1000 + (unsigned long long)(tv.tv_usec) / 1000;
    }

    uint8_t read_half() {
        /*
            read four bits, BIT_DELAY ms of delay is one bit
        */
        char buf[0x10] = {};

        uint64_t t1 = get_time();
        if(read(conn_fd, buf, 1) <= 0) {
            fail("read1");
        }

        uint64_t t2 = get_time();
        if(read(conn_fd, buf, 1) <= 0) {
            fail("read2");
        }

        uint64_t t3 = get_time();
        if(read(conn_fd, buf, 1) <= 0) {
            fail("read3");
        }

        uint64_t t4 = get_time();
        if(read(conn_fd, buf, 1) <= 0) {
            fail("read4");
        }

        uint64_t t5 = get_time();

        const int BIT_DELAY = 300;
        uint8_t b1 = (t2 - t1) >= BIT_DELAY;
        uint8_t b2 = (t3 - t2) >= BIT_DELAY;
        uint8_t b3 = (t4 - t3) >= BIT_DELAY;
        uint8_t b4 = (t5 - t4) >= BIT_DELAY;

        uint8_t final = (b1 << 3) | (b2 << 2) | (b3 << 1) | b4;
        if(send("OK") < 0){
            fail("confirm");
        }

        return final;
    }

    uint8_t read1() {
        return read_half() << 4 | read_half();
    }

    uint16_t read2() {
        return read1() << 8 | read1();
    }

    uint8_t* read_n(uint32_t n) {
        auto* buffer = new uint8_t[n];
        int recved;
        if((recved = read(conn_fd, buffer, n)) < 0) {
            delete []buffer;
            fail("read_n");
        }

        if(recved != n){
            delete []buffer;
            fail("recved != n");
        }

        if(send("OK") < 0){
            delete []buffer;
            fail("confirm");
        }
        return buffer;
    }
};
