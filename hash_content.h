#include <linux/gfp.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/slab.h>

struct hash_content {
    char *data;
    char *request;
    struct hlist_node node;
};

void init_hash_table(void);

void hash_insert(const char *request, char *data);

void hash_check(const char *request);