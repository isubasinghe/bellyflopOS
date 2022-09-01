
#ifndef SPAWNSTORE_H
#define SPAWNSTORE_H
#include <collections/list.h>
#include <barrelfish_kpi/types.h>
#include <stdbool.h>

struct spawninfo;

struct spawnstore {
    collections_listnode *entry;
};

struct spawnstore *get_default_spawnstore(void);

bool spawnstore_init(struct spawnstore *ss);
bool spawnstore_add(struct spawnstore *ss, struct spawninfo *sinf);
bool spawnstore_get(struct spawnstore *ss, domainid_t pid, struct spawninfo **si,
                    uint32_t *ith);
bool spawnstore_remove_by_pid(struct spawnstore *ss, domainid_t pid);
size_t spawnstore_size(struct spawnstore *ss);
bool spawnstore_get_by_name(struct spawnstore *ss, struct spawninfo **sinf, char *name);
bool spawnstore_get_all_pids(struct spawnstore *ss, domainid_t *pids, size_t num_pids);
bool spawnstore_destroy(struct spawnstore *ss);

#endif  // SPAWNSTORE_H
