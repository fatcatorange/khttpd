#include <linux/net.h>
#include "http_server.h"

typedef int (*timer_callback)(void *);

typedef struct {
    size_t key;  // time
    bool deleted;
    timer_callback callback;
    void *object;
} timer_node;

int pq_timer_init(void);
void handle_expired_timers(void);

timer_node *add_pq_timer(void *object, size_t timeout, timer_callback cb);
void del_pq_timer(timer_node *node);