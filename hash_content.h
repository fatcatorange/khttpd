#include <linux/gfp.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/slab.h>

struct hash_content {
    struct list_head *head;
    char *request;
    struct hlist_node node;
};

void init_hash_table(void);

void hash_insert(const char *request, struct list_head *head);

bool hash_check(const char *request, struct list_head **head);

void hash_clear(void);