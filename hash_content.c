#include "hash_content.h"

DEFINE_READ_MOSTLY_HASHTABLE(ht, 8);

void init_hash_table(void)
{
    hash_init(ht);
}

void hash_insert(const char *request, char *data)
{
    char *insert_data = kmalloc(strlen(data) + 1, GFP_KERNEL);
    memcpy(insert_data, data, strlen(data) + 1);
    u32 original_key = jhash(request, strlen(request), 0);
    u8 key = (u8) (original_key % 256);
    struct hash_content *content =
        kmalloc(sizeof(struct hash_content), GFP_KERNEL);
    content->data = kmalloc(strlen(data) + 1, GFP_KERNEL);
    content->request = kmalloc(strlen(request) + 1, GFP_KERNEL);
    memcpy(content->data, data, strlen(data) + 1);
    memcpy(content->request, request, strlen(data) + 1);
    hash_add(ht, &content->node, key);
}

void hash_check(const char *request)
{
    u32 original_key = jhash(request, strlen(request), 0);
    u8 key = (u8) (original_key % 256);
    struct hash_content *now;
    rcu_read_lock();
    hash_for_each_possible(ht, now, node, key)
    {
        if (strcmp(request, now->request) == 0) {
            printk("now request: %s\n", request);
        }
    }
    rcu_read_unlock();
}