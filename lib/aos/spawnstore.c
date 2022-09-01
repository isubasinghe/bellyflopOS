#include <aos/spawnstore.h>
#include <spawn/spawn.h>

static struct spawnstore *global_spawnstore = NULL;
static struct thread_mutex ss_mutex;

struct spawnstore *get_default_spawnstore(void) 
{
    if(global_spawnstore == NULL) { 
        // This is very dangerous.
        global_spawnstore = malloc(sizeof(struct spawnstore));
        thread_mutex_init(&ss_mutex);
        assert(global_spawnstore != NULL);
        global_spawnstore->entry = NULL;
        spawnstore_init(global_spawnstore);
        assert(global_spawnstore->entry != NULL);
    }
    return global_spawnstore;
}

bool spawnstore_init(struct spawnstore *ss) 
{
    thread_mutex_lock(&ss_mutex);
    collections_list_create(&ss->entry, free);
    thread_mutex_unlock(&ss_mutex);
    return true;
}



bool spawnstore_add(struct spawnstore *ss, struct spawninfo *sinf) 
{
    thread_mutex_lock(&ss_mutex);
    if(collections_list_insert(ss->entry, sinf)) {
        thread_mutex_unlock(&ss_mutex);
        return false;
    }
    thread_mutex_unlock(&ss_mutex);
    return true;
}

bool spawnstore_get(struct spawnstore *ss, domainid_t pid, struct spawninfo **si,
                    uint32_t *ith)
{
    assert(ss != NULL);
    assert(ss->entry != NULL);
    thread_mutex_lock(&ss_mutex);
    collections_list_traverse_start(ss->entry);
    uint32_t i = 0;
    *si = NULL;
    while (1) {
        struct spawninfo *sinf = (struct spawninfo *)collections_list_traverse_next(
            ss->entry);
        if (sinf == NULL) {
            break;
        } else {
            if (sinf->pid == pid) {
                *si = sinf;
                if (ith != NULL) {
                    *ith = i;
                }
                break;
            }
            i++;
        }
    }
    collections_list_traverse_end(ss->entry);
    thread_mutex_unlock(&ss_mutex);
    return *si != NULL;
}

static int32_t pid_equal(void *a, void *b) {
    struct spawninfo *si = (struct spawninfo *)a;
    size_t pid_arg = (size_t)b;
    domainid_t pid2 = (domainid_t) pid_arg;
    return si->pid == pid2;
}

bool spawnstore_remove_by_pid(struct spawnstore *ss, domainid_t pid) 
{
    thread_mutex_lock(&ss_mutex);
    size_t pid_arg = pid;
    struct spawninfo *sinf = collections_list_remove_if(
        global_spawnstore->entry, &pid_equal, (void*) pid_arg);
    if(sinf == NULL) {
        thread_mutex_unlock(&ss_mutex);
        return false;
    }
    thread_mutex_unlock(&ss_mutex);
    return true;
}


bool spawnstore_get_by_name(struct spawnstore *ss, struct spawninfo **sinf, char *name)
{
    assert(ss != NULL);
    assert(ss->entry != NULL);
    thread_mutex_lock(&ss_mutex);
    collections_list_traverse_start(ss->entry);
    while (1) {
        struct spawninfo *si = (struct spawninfo *)collections_list_traverse_next(
            ss->entry);
        if (si == NULL) {
            break;
        } else {
            if (strcmp(si->binary_name, name) == 0) {
                *sinf = si;
                collections_list_traverse_end(ss->entry);
                thread_mutex_unlock(&ss_mutex);
                return true;
            }
        }
    }
    collections_list_traverse_end(ss->entry);
    thread_mutex_unlock(&ss_mutex);
    return false;
}

bool spawnstore_get_all_pids(struct spawnstore *ss, domainid_t *pids, size_t num_pids)
{
    assert(ss != NULL);
    assert(ss->entry != NULL);
    thread_mutex_lock(&ss_mutex);
    size_t index = 0;

    collections_list_traverse_start(ss->entry);
    while (1) {
        struct spawninfo *si = (struct spawninfo *)collections_list_traverse_next(
            ss->entry);
        if (si == NULL) {
            break;
        } else {
            if (index >= num_pids) {
                collections_list_traverse_end(ss->entry);
                thread_mutex_unlock(&ss_mutex);
                return false;
            }
            pids[index] = si->pid;
            index++;
        }
    }
    collections_list_traverse_end(ss->entry);
    thread_mutex_unlock(&ss_mutex);
    return true;
}

size_t spawnstore_size(struct spawnstore *ss)
{
    assert(ss != NULL);
    assert(ss->entry != NULL);
    thread_mutex_lock(&ss_mutex);
    size_t res = collections_list_size(ss->entry);
    thread_mutex_unlock(&ss_mutex);
    return res;
}

bool spawnstore_destroy(struct spawnstore *ss) 
{
    thread_mutex_lock(&ss_mutex);
    collections_list_release(ss->entry);
    thread_mutex_unlock(&ss_mutex);
    return true;
}
