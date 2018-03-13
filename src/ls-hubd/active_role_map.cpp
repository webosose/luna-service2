// Copyright (c) 2008-2018 LG Electronics, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

#include "active_role_map.hpp"

#include "error.h"
#include "role.hpp"
#include "transport.h"

/// @cond INTERNAL
/// @addtogroup LunaServiceHubSecurity
/// @{

/**
 * Hash of pid to LSHubRole.
 *
 * These are roles that are currently in use by processes
 */
static GHashTable*
LSHubActiveRoleMapGet()
{
    static GHashTablePointer active_role_map =
        mk_ptr(g_hash_table_new_full(g_direct_hash, g_direct_equal, nullptr, (GDestroyNotify) LSHubRoleUnref),
               g_hash_table_destroy);

    LS_ASSERT(active_role_map);

    return active_role_map.get();
}

bool
LSHubActiveRoleMapAddRef(pid_t pid, LSHubRole *role, LSError *lserror)
{
    LOG_LS_DEBUG("%s: attempting to ref pid: " LS_PID_PRINTF_FORMAT " in role map...\n", __func__, LS_PID_PRINTF_CAST(pid));

    /* if it already exists in hash table then bump up its ref count */
    LSHubRole *hashed_role = LSHubActiveRoleMapLookup(pid);

    if (hashed_role)
    {
        /* active role already exists for this pid, so bump ref count */
        LSHubRoleRef(hashed_role);
        LOG_LS_DEBUG("%s: bump ref count...\n", __func__);
    }
    else
    {
        /* ref and insert new role */
        LSHubRoleRef(role);
        g_hash_table_insert(LSHubActiveRoleMapGet(), GINT_TO_POINTER(pid), role);
        LOG_LS_DEBUG("%s: ref and insert...\n", __func__);
    }

    LOG_LS_DEBUG("%s: success\n", __func__);

    return true;
}

bool
LSHubActiveRoleMapUnref(pid_t pid)
{
    LOG_LS_DEBUG("%s: attempting to unref pid: " LS_PID_PRINTF_FORMAT " from role map...\n", __func__, LS_PID_PRINTF_CAST(pid));

    /* if the role ref count goes to 0, we remove it from the hash table */
    LSHubRole *role = LSHubActiveRoleMapLookup(pid);

    if (role)
    {
        if (LSHubRoleUnref(role))
        {
            /* ref count for this role went to 0, so remove the reference to
             * it in the hash table */
            g_hash_table_steal(LSHubActiveRoleMapGet(), GINT_TO_POINTER(pid));
            LOG_LS_DEBUG("%s: removed...\n", __func__);
            return true;
        }

        LOG_LS_DEBUG("unref'ed\n");
    }

    return false;
}


LSHubRole*
LSHubActiveRoleMapLookup(pid_t pid)
{
    LOG_LS_DEBUG("%s: look up pid: " LS_PID_PRINTF_FORMAT " in role map\n", __func__, LS_PID_PRINTF_CAST(pid));

    return static_cast<LSHubRole *>(g_hash_table_lookup(LSHubActiveRoleMapGet(), GINT_TO_POINTER(pid)));
}

bool
LSHubActiveRoleMapClientRemove(const _LSTransportClient *client, LSError *lserror)
{
    // Role for client with application Id not referenced in active role map
    if (_LSTransportClientGetApplicationId(client))
    {
        return true;
    }

    /* look up the role in active role map and unref it */
    const _LSTransportCred *cred = _LSTransportClientGetCred(client);

    if (!cred)
    {
        _LSErrorSet(lserror, MSGID_LSHUB_NO_CLIENT, -1, "Unable to get client credentials");
        return false;
    }

    pid_t pid = _LSTransportCredGetPid(cred);

    LSHubActiveRoleMapUnref(pid);

    return true;
}

/// @} END OF GROUP LunaServiceHubSecurity
/// @endcond
