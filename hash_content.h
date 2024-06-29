#include <linux/gfp.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/slab.h>
#include "timer.h"

#define CACHE_TIME_OUT 20000

struct hash_content {
    struct list_head *head;
    char *request;
    struct hlist_node node;
    timer_node *timer;
};

void init_hash_table(void);

void hash_insert(const char *request, struct list_head *head);

int hash_delete(void *con);

bool hash_check(const char *request, struct list_head **head);

void hash_clear(void);