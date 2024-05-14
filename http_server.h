#ifndef KHTTPD_HTTP_SERVER_H
#define KHTTPD_HTTP_SERVER_H

#include <net/sock.h>

struct http_server_param {
    struct socket *listen_socket;
};

extern int http_server_daemon(void *arg);

extern int kthread_start_check(void);

extern int kthread_end_check(void *data);

#endif
