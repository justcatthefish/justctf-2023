#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>

bool debug = false;

__attribute__ ((noinline)) int app_connect_to(const char* ip, const char* port) {
    int port_int = atoi(port);

    struct sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(ip);
    addr.sin_port = htons(port_int);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        perror("socket");
        return -1;
    }

    if (connect(fd, (struct sockaddr*) &addr, sizeof(addr)) == -1) {
        perror("connect");
        close(fd);
        return -1;
    }

    return fd;
}

__attribute__ ((noinline)) void app_set_blocking(int fd, bool blocking) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl == -1)
        return;
    if (blocking)
        fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
    else
        fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

__attribute__ ((noinline)) void app_write_fully(int fd, const void* data, size_t len) {
    app_set_blocking(fd, true);
    while (len > 0) {
        ssize_t wrote_bytes = write(fd, data, len);
        if (wrote_bytes == -1) {
            printf("<fd:%d>\n", fd);
            perror("write");
            exit(2);
        }
        data = (void *) ((uintptr_t) data + wrote_bytes);
        len -= wrote_bytes;
    }
    app_set_blocking(fd, false);
}

using input_message_cb = void* (*)(int64_t fd, void* data, size_t len);
input_message_cb input_message_callback;
int64_t input_message_fd;
void* input_message_data;
size_t input_message_len;
int input_message_revents;

__attribute__ ((noinline)) void app_handle_input(const char* handler_name) {
    if (debug) {
        fprintf(stderr, "%s [fd=%d, revents=%d, data=%p, len=%llu]\n",
               handler_name, (int)input_message_fd, input_message_revents, input_message_data, (unsigned long long) input_message_len);
    }
    input_message_callback(input_message_fd, input_message_data, input_message_len);
}

__attribute__ ((noinline)) void app_error(const char* text) {
    throw std::runtime_error(debug ? text : "");
}

int main(int argc, char* argv[]) {
    if (argc != 3 && argc != 4) {
        printf("usage: %s <ip> <port>\n", argv[0]);
        return 1;
    }

    int argi = 1;
    if (!strcmp(argv[1], "-debug")) {
        debug = true;
        argi = 2;
    }

    int socket_fd = app_connect_to(argv[argi], argv[argi + 1]);
    if (socket_fd == -1) {
        return 1;
    }

    int stdin_fd = 0;
    char stdin_buf[1024] {};

    size_t socket_buf_pos = 0;
    char socket_buf[16 * 1024] {};

    app_set_blocking(stdin_fd, false);
    app_set_blocking(socket_fd, false);

    struct pollfd pfd[2] {};
    pfd[0].fd = stdin_fd;
    pfd[0].events = POLLIN;
    pfd[1].fd = socket_fd;
    pfd[1].events = POLLIN;

    int stop_flag = 0;

    while (!stop_flag) {
        try {
            int retval = poll(pfd, 2, -1);
            if (retval == -1) {
                perror("poll");
                return 1;
            }

            if (pfd[0].revents & POLLIN) {
                ssize_t read_bytes = read(stdin_fd, stdin_buf, sizeof(stdin_buf));
                // app_write_fully(socket_fd, stdin_buf, read_bytes);
                input_message_callback = (input_message_cb) app_write_fully;
                input_message_fd = socket_fd;
                input_message_data = stdin_buf;
                input_message_len = (size_t) read_bytes;
                input_message_revents = pfd[0].revents;
                app_handle_input("send");
            }
            if (pfd[1].revents & POLLIN) {
                ssize_t read_bytes = read(socket_fd, socket_buf + socket_buf_pos, sizeof(socket_buf) - socket_buf_pos);
                socket_buf_pos += read_bytes;
                char *p = (char *) memchr(socket_buf, '\n', socket_buf_pos);
                if (p) {
                    //app_write_fully(1, socket_buf, socket_buf_pos);
                    input_message_callback = (input_message_cb) app_write_fully;
                    input_message_fd = 1;
                    input_message_data = socket_buf;
                    input_message_len = (size_t) (p + 1 - socket_buf);
                    input_message_revents = pfd[1].revents;
                    app_handle_input("receive");
                    memcpy(socket_buf, p + 1, socket_buf_pos - (p + 1 - socket_buf));
                    socket_buf_pos -= (p + 1 - socket_buf);
                } else if (socket_buf_pos == sizeof(socket_buf)) {
                    app_error("Ran out of buffer space!");
                }
            }
        } catch (std::exception& e) {
            stop_flag = 1;
        }
    }

    return stop_flag;
}