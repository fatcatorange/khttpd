#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "http_server.h"
#include <linux/fs.h>
#include <linux/jiffies.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/sched/signal.h>
#include <linux/spinlock.h>
#include "hash_content.h"
#include "http_parser.h"
#include "timer.h"

#define CRLF "\r\n"

#define HTTP_RESPONSE_200_DUMMY                               \
    ""                                                        \
    "HTTP/1.1 200 OK" CRLF "Server: " KBUILD_MODNAME CRLF     \
    "Content-Type: text/plain" CRLF "Content-Length: 12" CRLF \
    "Connection: Close" CRLF CRLF "Hello World!" CRLF
#define HTTP_RESPONSE_200_KEEPALIVE_DUMMY                     \
    ""                                                        \
    "HTTP/1.1 200 OK" CRLF "Server: " KBUILD_MODNAME CRLF     \
    "Content-Type: text/plain" CRLF "Content-Length: 12" CRLF \
    "Connection: Keep-Alive" CRLF CRLF "Hello World!" CRLF
#define HTTP_RESPONSE_501                                              \
    ""                                                                 \
    "HTTP/1.1 501 Not Implemented" CRLF "Server: " KBUILD_MODNAME CRLF \
    "Content-Type: text/plain" CRLF "Content-Length: 21" CRLF          \
    "Connection: Close" CRLF CRLF "501 Not Implemented" CRLF
#define HTTP_RESPONSE_501_KEEPALIVE                                    \
    ""                                                                 \
    "HTTP/1.1 501 Not Implemented" CRLF "Server: " KBUILD_MODNAME CRLF \
    "Content-Type: text/plain" CRLF "Content-Length: 21" CRLF          \
    "Connection: KeepAlive" CRLF CRLF "501 Not Implemented" CRLF

#define RECV_BUFFER_SIZE 4096
#define SEND_BUFFER_SIZE 256
#define BUFFER_SIZE 256
#define TIME_OUT 10000

struct khttpd_service daemon_list = {.is_stopped = false};
static struct task_struct *expire_check;
extern struct workqueue_struct *khttpd_wq;

struct tag_content {
    struct list_head tag_list;
    char url[SEND_BUFFER_SIZE];
};

struct http_request {
    struct socket *socket;
    enum http_method method;
    char request_url[128];
    int complete;
    struct dir_context dir_context;
    struct list_head node;
    struct work_struct khttpd_work;
    struct list_head *tag_list;
    timer_node *t_node;
};

static int http_server_recv(struct socket *sock, char *buf, size_t size)
{
    struct kvec iov = {.iov_base = (void *) buf, .iov_len = size};
    struct msghdr msg = {.msg_name = 0,
                         .msg_namelen = 0,
                         .msg_control = NULL,
                         .msg_controllen = 0,
                         .msg_flags = 0};
    return kernel_recvmsg(sock, &msg, &iov, 1, size, msg.msg_flags);
}

static int http_server_send(struct socket *sock, const char *buf, size_t size)
{
    struct msghdr msg = {.msg_name = NULL,
                         .msg_namelen = 0,
                         .msg_control = NULL,
                         .msg_controllen = 0,
                         .msg_flags = 0};
    int done = 0;
    while (done < size) {
        struct kvec iov = {
            .iov_base = (void *) ((char *) buf + done),
            .iov_len = size - done,
        };
        int length = kernel_sendmsg(sock, &msg, &iov, 1, iov.iov_len);
        if (length < 0) {
            printk("write error: %d\n", length);
            break;
        }
        done += length;
    }
    return done;
}

static _Bool tracedir(struct dir_context *dir_context,
                      const char *name,
                      int namelen,
                      loff_t offset,
                      u64 ino,
                      unsigned int d_type)
{
    if (strcmp(name, ".") && strcmp(name, "..")) {
        struct http_request *request =
            container_of(dir_context, struct http_request, dir_context);
        char buf[SEND_BUFFER_SIZE] = {0};
        char *des = kmalloc(strlen(request->request_url) + strlen(name) + 3,
                            GFP_KERNEL);
        if (strcmp(request->request_url, "/") != 0) {
            strncpy(des, request->request_url, strlen(request->request_url));
            strcat(des, "/");
            strcat(des, name);
        } else {
            strncpy(des, name, strlen(name));
        }
        snprintf(buf, SEND_BUFFER_SIZE,
                 "%lx\r\n<tr><td><a href=\"%s\">%s</a></td></tr>\r\n",
                 34 + strlen(des) + strlen(name), des, name);

        struct tag_content *content =
            kmalloc(sizeof(struct tag_content), GFP_KERNEL);
        INIT_LIST_HEAD(&content->tag_list);
        strncpy(content->url, buf, strlen(buf));
        list_add_tail(&content->tag_list, request->tag_list);

        http_server_send(request->socket, buf, strlen(buf));
    }

    return 1;
}

static void send_http_header(struct socket *socket,
                             int status,
                             const char *status_msg,
                             char *type,
                             int length,
                             char *conn_msg)
{
    char buf[SEND_BUFFER_SIZE] = {0};
    snprintf(buf, SEND_BUFFER_SIZE,
             "HTTP/1.1 %d %s\r\n     \
                Content-Type: %s\r\n    \
                Content-Length: %d\r\n  \
                Connection: %s\r\n\r\n",
             status, status_msg, type, length, conn_msg);
    http_server_send(socket, buf, strlen(buf));
}

static void send_http_content(struct socket *socket, char *content)
{
    char buf[SEND_BUFFER_SIZE] = {0};
    snprintf(buf, SEND_BUFFER_SIZE, "%s\r\n", content);
    http_server_send(socket, buf, strlen(buf));
}

static inline int read_file(struct file *fp, char *buf)
{
    return kernel_read(fp, buf, fp->f_inode->i_size, 0);
}

static void catstr(char *res, char *first, char *second)
{
    int first_size = strlen(first);
    int second_size = strlen(second);
    memset(res, 0, BUFFER_SIZE);
    memcpy(res, first, first_size);
    memcpy(res + first_size, second, second_size);
}

static bool handle_directory(struct http_request *request)
{
    struct file *fp;
    char pwd[BUFFER_SIZE] = {0};

    request->dir_context.actor = tracedir;
    if (request->method != HTTP_GET) {
        send_http_header(request->socket, HTTP_STATUS_NOT_IMPLEMENTED,
                         http_status_str(HTTP_STATUS_NOT_IMPLEMENTED),
                         "text/plain", 19, "close");
        send_http_content(request->socket, "501 Not Implemented");
        return false;
    }

    catstr(pwd, daemon_list.dir_path, request->request_url);
    fp = filp_open(pwd, O_RDONLY, 0);

    if (IS_ERR(fp)) {
        send_http_header(request->socket, HTTP_STATUS_NOT_FOUND,
                         http_status_str(HTTP_STATUS_NOT_FOUND), "text/plain",
                         14, "close");
        send_http_content(request->socket, "404 Not Found");
        kernel_sock_shutdown(request->socket, SHUT_RDWR);
        return false;
    }

    if (S_ISDIR(fp->f_inode->i_mode)) {
        char buf[SEND_BUFFER_SIZE] = {0};
        snprintf(buf, SEND_BUFFER_SIZE, "HTTP/1.1 200 OK\r\n%s%s%s",
                 "Connection: Keep-Alive\r\n", "Content-Type: text/html\r\n",
                 "Transfer-Encoding: chunked\r\n\r\n");
        http_server_send(request->socket, buf, strlen(buf));

        snprintf(
            buf, SEND_BUFFER_SIZE, "7B\r\n%s%s%s%s", "<html><head><style>\r\n",
            "body{font-family: monospace; font-size: 15px;}\r\n",
            "td {padding: 1.5px 6px;}\r\n", "</style></head><body><table>\r\n");
        http_server_send(request->socket, buf, strlen(buf));

        if (strcmp(request->request_url, "")) {
            snprintf(buf, SEND_BUFFER_SIZE,
                     "%lx\r\n<tr><td><a href=\"%s%s\">..</a></td></tr>\r\n",
                     36 + strlen(request->request_url) + 4,
                     request->request_url, "/../");
            http_server_send(request->socket, buf, strlen(buf));
        }

        struct list_head *head;
        printk("%s\n", request->request_url);
        if (!hash_check(request->request_url, &head)) {
            head = kmalloc(sizeof(struct list_head), GFP_KERNEL);
            INIT_LIST_HEAD(head);
            request->tag_list = head;
            iterate_dir(fp, &request->dir_context);
            hash_insert(request->request_url, head);
        } else {
            struct tag_content *now_content;
            list_for_each_entry (now_content, head, tag_list) {
                http_server_send(request->socket, now_content->url,
                                 strlen(now_content->url));
            }
        }


        snprintf(buf, SEND_BUFFER_SIZE, "16\r\n</table></body></html>\r\n");
        http_server_send(request->socket, buf, strlen(buf));
        http_server_send(request->socket, "0\r\n\r\n\r\n",
                         strlen("0\r\n\r\n\r\n"));

    } else if (S_ISREG(fp->f_inode->i_mode)) {
        char *read_data = kmalloc(fp->f_inode->i_size, GFP_KERNEL);
        int ret = read_file(fp, read_data);

        send_http_header(request->socket, HTTP_STATUS_OK,
                         http_status_str(HTTP_STATUS_OK), "text/plain", ret,
                         "Close");
        http_server_send(request->socket, read_data, ret);
        kfree(read_data);
        kernel_sock_shutdown(request->socket, SHUT_RDWR);
    }
    //
    filp_close(fp, NULL);
    return true;
}


static int http_server_response(struct http_request *request, int keep_alive)
{
    // pr_info("requested_url = %s\n", request->request_url);
    int ret = handle_directory(request);
    if (ret > 0)
        return -1;
    return 0;
}

static int http_parser_callback_message_begin(http_parser *parser)
{
    struct http_request *request = parser->data;
    struct socket *socket = request->socket;
    memset(request, 0x00, sizeof(struct http_request));
    request->socket = socket;
    return 0;
}

static int http_parser_callback_request_url(http_parser *parser,
                                            const char *p,
                                            size_t len)
{
    struct http_request *request = parser->data;
    if (p[len - 1] == '/')
        len--;
    strncat(request->request_url, p, len);
    return 0;
}

static int http_parser_callback_header_field(http_parser *parser,
                                             const char *p,
                                             size_t len)
{
    return 0;
}

static int http_parser_callback_header_value(http_parser *parser,
                                             const char *p,
                                             size_t len)
{
    return 0;
}

static int http_parser_callback_headers_complete(http_parser *parser)
{
    struct http_request *request = parser->data;
    request->method = parser->method;
    return 0;
}

static int http_parser_callback_body(http_parser *parser,
                                     const char *p,
                                     size_t len)
{
    return 0;
}

static int http_parser_callback_message_complete(http_parser *parser)
{
    struct http_request *request = parser->data;
    http_server_response(request, http_should_keep_alive(parser));
    request->complete = 1;
    return 0;
}

int clear_socket(struct socket *socket)
{
    kernel_sock_shutdown(socket, SHUT_RD);
    return 0;
}

static void http_server_worker(struct work_struct *w)
{
    char *buf;
    struct http_parser parser;
    struct http_parser_settings setting = {
        .on_message_begin = http_parser_callback_message_begin,
        .on_url = http_parser_callback_request_url,
        .on_header_field = http_parser_callback_header_field,
        .on_header_value = http_parser_callback_header_value,
        .on_headers_complete = http_parser_callback_headers_complete,
        .on_body = http_parser_callback_body,
        .on_message_complete = http_parser_callback_message_complete};
    struct http_request request;
    struct socket *socket =
        container_of(w, struct http_request, khttpd_work)->socket;

    allow_signal(SIGKILL);
    allow_signal(SIGTERM);

    buf = kzalloc(RECV_BUFFER_SIZE, GFP_KERNEL);
    if (!buf) {
        printk("can't allocate memory!\n");
        return;
    }
    request.socket = socket;
    http_parser_init(&parser, HTTP_REQUEST);
    parser.data = &request;
    timer_node *t_node = add_pq_timer(request.socket, TIME_OUT, clear_socket);

    while (!kthread_should_stop()) {
        int ret = http_server_recv(socket, buf, RECV_BUFFER_SIZE - 1);
        if (ret <= 0) {
            printk("%p disconnected!", socket);
            break;
        }
        // printk("%s\n", buf);
        // printk("%p %p\n", socket, t_node);
        // t_node->deleted = true;
        del_pq_timer(t_node);
        t_node = add_pq_timer(request.socket, TIME_OUT, clear_socket);
        http_parser_execute(&parser, &setting, buf, ret);
        if (request.complete && !http_should_keep_alive(&parser))
            break;
        memset(buf, 0, RECV_BUFFER_SIZE);
    }


    kernel_sock_shutdown(socket, SHUT_RDWR);
    sock_release(socket);
    kfree(buf);
    return;
}

static void free_work(void)
{
    struct http_request *l, *tar;
    /* cppcheck-suppress uninitvar */

    list_for_each_entry_safe (tar, l, &daemon_list.head, node) {
        kernel_sock_shutdown(tar->socket, SHUT_RDWR);
        flush_work(&tar->khttpd_work);
        sock_release(tar->socket);
        kfree(tar);
    }
}

static struct work_struct *create_work(struct socket *sk)
{
    struct http_request *work;


    if (!(work = kmalloc(sizeof(struct http_request), GFP_KERNEL)))
        return NULL;

    work->socket = sk;

    INIT_WORK(&work->khttpd_work, http_server_worker);

    list_add(&work->node, &daemon_list.head);

    return &work->khttpd_work;
}

int handle_expire(void *arg)
{
    while (!kthread_should_stop()) {
        handle_expired_timers();
        msleep(1000);
    }
    return 0;
}

int http_server_daemon(void *arg)
{
    struct socket *socket;
    struct work_struct *work;
    struct http_server_param *param = (struct http_server_param *) arg;

    allow_signal(SIGKILL);
    allow_signal(SIGTERM);

    INIT_LIST_HEAD(&daemon_list.head);

    expire_check = kthread_run(handle_expire, NULL, KBUILD_MODNAME);

    if (IS_ERR(expire_check)) {
        pr_err("can't start expire check\n");
        return PTR_ERR(expire_check);
    }


    while (!kthread_should_stop()) {
        int err = kernel_accept(param->listen_socket, &socket, 0);
        if (err < 0) {
            if (signal_pending(current))
                break;
            printk("kernel_accept() error: %d\n", err);
            continue;
        }

        if (unlikely(!(work = create_work(socket)))) {
            printk(KERN_ERR ": create work error, connection closed\n");
            kernel_sock_shutdown(socket, SHUT_RDWR);
            sock_release(socket);
            continue;
        }

        /* start server worker */
        queue_work(khttpd_wq, work);
    }

    printk(": daemon shutdown in progress...\n");

    daemon_list.is_stopped = true;
    free_work();

    return 0;
}
