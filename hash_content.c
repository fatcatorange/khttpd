#include "hash_content.h"

#define SEND_BUFFER_SIZE 256

DEFINE_HASHTABLE(ht, 8);


struct tag_content {
    struct list_head tag_list;
    char url[SEND_BUFFER_SIZE];
};

void init_hash_table(void)
{
    hash_init(ht);
}

void hash_insert(const char *request, struct list_head *head)
{
    u32 original_key = jhash(request, strlen(request), 0);
    u8 key = (u8) (original_key % 256);
    struct hash_content *content =
        kmalloc(sizeof(struct hash_content), GFP_KERNEL);
    content->head = head;
    content->request = kmalloc(strlen(request) + 1, GFP_KERNEL);
    memcpy(content->request, request, strlen(request) + 1);
    hash_add_rcu(ht, &content->node, key);
}

bool hash_check(const char *request, struct list_head **head)
{
    u32 original_key = jhash(request, strlen(request), 0);
    u8 key = (u8) (original_key % 256);
    struct hash_content *now = NULL;
    rcu_read_lock();
    hash_for_each_possible_rcu(ht, now, node, key)
    {
        if (strcmp(request, now->request) == 0) {
            *head = now->head;
            rcu_read_unlock();
            return true;
        }
    }

    rcu_read_unlock();
    return false;
}

void hash_clear(void)
{
    struct hash_content *entry = NULL;
    struct hlist_node *tmp = NULL;
    struct tag_content *now;
    struct tag_content *tag_temp;
    unsigned int bucket;

    hash_for_each_safe(ht, bucket, tmp, entry, node)
    {
        list_for_each_entry_safe (now, tag_temp, entry->head, tag_list) {
            list_del(&now->tag_list);
            kfree(now);
        }
        hash_del(&entry->node);
        kfree(entry);
    }
}