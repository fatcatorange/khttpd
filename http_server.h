#ifndef KHTTPD_HTTP_SERVER_H
#define KHTTPD_HTTP_SERVER_H

#include <linux/tcp.h>
#include <net/sock.h>


struct http_server_param {
    struct socket *listen_socket;
};

struct khttpd_service {
    bool is_stopped;
    struct list_head head;
    char *dir_path;
};


extern struct khttpd_service daemon_list;

extern int http_server_daemon(void *arg);

extern int kthread_start_check(void);

extern int kthread_end_check(void *data);

int clear_socket(void *socket);

#endif
