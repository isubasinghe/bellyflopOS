#include <aos/types.h>
#include <assert.h>
#include <stdio.h>

coreid_t did_get_coreid(domainid_t did)
{
    return did >> 24;
}

local_domainid_t did_get_local_did(domainid_t did)
{
    return did & 0xffffff;
}

domainid_t did_from(coreid_t coreid, local_domainid_t local_did)
{
    assert(local_did <= 0xffffff);

    uint32_t coreid_uint32 = coreid;
    return (coreid_uint32 << 24) | local_did;
}

domainid_t sid_get_domainid(serviceid_t sid)
{
    return sid >> 32;
}

domainid_t sid_get_coreid(serviceid_t sid)
{
    return did_get_coreid(sid_get_domainid(sid));
}

local_serviceid_t sid_get_local_sid(serviceid_t sid)
{
    return (local_serviceid_t)(sid & 0xffffffff);
}

serviceid_t sid_from(domainid_t did, local_serviceid_t lsid)
{
    uint64_t did_uint64 = did;
    return (did_uint64 << 32) | lsid;
}

void sid_to_str(serviceid_t sid, char str[64]) {
    domainid_t did = sid_get_domainid(sid);
    sprintf(str, "%d.%d.%d", did_get_coreid(did), did_get_local_did(did), sid_get_local_sid(sid));
}