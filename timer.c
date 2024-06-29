#include "timer.h"
#include <linux/spinlock.h>
#define PQ_DEFAULT_SIZE 10

typedef int (*prio_queue_comparator)(void *pi, void *pj);

typedef struct {
    void **priv;
    size_t nalloc;
    size_t size;
    prio_queue_comparator comp;
    spinlock_t spinlock;
} prio_queue_t;

static bool prio_queue_init(prio_queue_t *ptr,
                            prio_queue_comparator comp,
                            size_t size)
{
    ptr->priv = kmalloc(sizeof(void *) * (size + 1), GFP_KERNEL);
    if (!ptr->priv) {
        printk("malloc failed in prio_queue_init!");
        return false;
    }
    printk("malloc %ld\n", sizeof(void *) * (size + 1));
    ptr->nalloc = 0;
    ptr->size = size + 1;
    ptr->comp = comp;
    return true;
}

static inline bool prio_queue_is_empty(prio_queue_t *ptr)
{
    return ptr->nalloc == 0;
}

static inline size_t prio_queue_size(prio_queue_t *ptr)
{
    return ptr->nalloc;
}

static inline void *prio_queue_min(prio_queue_t *ptr)
{
    return prio_queue_is_empty(ptr) ? NULL : ptr->priv[1];
}

static bool resize(prio_queue_t *ptr, size_t new_size)
{
    printk("start resize");
    void **new_ptr = kmalloc(sizeof(void *) * new_size, GFP_KERNEL);
    if (!new_ptr) {
        printk("malloc failed in resize!");
        return false;
    }

    memcpy(new_ptr, ptr->priv, sizeof(void *) * (ptr->nalloc + 1));
    kfree(ptr->priv);
    ptr->priv = new_ptr;
    ptr->size = new_size;
    printk("end resize");
    return true;
}

static inline void pq_swap(prio_queue_t *ptr, size_t i, size_t j)
{
    void *tmp = ptr->priv[i];
    ptr->priv[i] = ptr->priv[j];
    ptr->priv[j] = tmp;
}

static inline void pq_swim(prio_queue_t *ptr, size_t k)
{
    while (k > 1 && ptr->comp(ptr->priv[k], ptr->priv[k / 2])) {
        pq_swap(ptr, k, k / 2);
        k /= 2;
    }
}

static size_t pq_sink(prio_queue_t *ptr, size_t k)
{
    size_t nalloc = ptr->nalloc;
    while (2 * k <= nalloc) {
        size_t j = 2 * k;
        if (ptr->comp(ptr->priv[j + 1], ptr->priv[j]))
            j++;
        if (!ptr->comp(ptr->priv[j], ptr->priv[k]))
            break;
        pq_swap(ptr, j, k);
        k = j;
    }


    return k;
}

static bool prio_queue_delmin(prio_queue_t *ptr)
{
    if (prio_queue_is_empty(ptr))
        return true;
    printk("start delmin");
    pq_swap(ptr, 1, ptr->nalloc);
    printk("start sink");
    ptr->nalloc--;
    pq_sink(ptr, 1);
    printk("finished sink");
    return true;
}

static bool prio_queue_insert(prio_queue_t *ptr, void *item)
{
    printk("start insert");
    if (ptr->nalloc + 1 == ptr->size) {
        if (!resize(ptr, ptr->size * 2))
            return false;
    }

    printk("nowpoint: %ld\n", ((timer_node *) (item))->key);
    ptr->nalloc++;
    ptr->priv[ptr->nalloc] = item;
    pq_swim(ptr, ptr->nalloc);
    return true;
}

static int timer_comp(void *ti, void *tj)
{
    return ((timer_node *) ti)->key < ((timer_node *) tj)->key ? 1 : 0;
}

static prio_queue_t timer;
static size_t current_msec;

static void time_update(void)
{
    struct timespec64 tv;
    ktime_get_ts64(&tv);
    current_msec = tv.tv_sec * 1000 + tv.tv_nsec / 1000000;
}

int pq_timer_init()
{
    bool ret = prio_queue_init(&timer, timer_comp, PQ_DEFAULT_SIZE);
    printk("init timer:%d", ret);
    spin_lock_init(&timer.spinlock);
    time_update();
    return 0;
}

void handle_expired_timers()
{
    bool ret;
    spin_lock(&timer.spinlock);
    while (!prio_queue_is_empty(&timer)) {
        printk("handle_expired_timers, size = %zu", prio_queue_size(&timer));
        time_update();
        void *tmp_node = prio_queue_min(&timer);
        timer_node *node = (timer_node *) (tmp_node);


        if (node->deleted) {
            ret = prio_queue_delmin(&timer);
            printk("del min: %d\n", ret);
            kfree(node);
            printk("end del min!");
            continue;
        }
        if (node->key > current_msec) {
            spin_unlock(&timer.spinlock);
            return;
        }

        printk("node = null? %d\n", node == NULL);

        if (node->callback) {
            node->callback(node->object);
        }
        printk("clear socket!");
        ret = prio_queue_delmin(&timer);
        printk("delmin!");
        kfree(node);
    }
    spin_unlock(&timer.spinlock);
}

timer_node *add_pq_timer(void *object, size_t timeout, timer_callback cb)
{
    spin_lock(&timer.spinlock);
    timer_node *node = kmalloc(sizeof(timer_node), GFP_KERNEL);
    if (!node) {
        printk("timer add malloc failed!");
        spin_unlock(&timer.spinlock);
        return node;
    }
    time_update();
    node->key = current_msec + timeout;
    node->deleted = false;
    node->callback = cb;
    node->object = object;

    prio_queue_insert(&timer, node);
    spin_unlock(&timer.spinlock);
    return node;
}

void del_pq_timer(timer_node *t_node)
{
    spin_lock(&timer.spinlock);
    if (t_node)
        t_node->deleted = true;
    spin_unlock(&timer.spinlock);
}