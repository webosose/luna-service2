// Copyright (c) 2014-2019 LG Electronics, Inc.
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

#include "active_permission_map.hpp"

#include "util.hpp"
#include "conf.hpp"
#include "transport.h"
#include "security.hpp"
#include "groups_map.hpp"
#include "permission.hpp"
#include "patternqueue.hpp"
#include "permissions_map.hpp"

#include <fstream>

void DumpToFileActivePerm(const char* filename, const char* dump)
{
    if (!filename) return;

    char full_path[256] = {0};
    strncpy(full_path, "/tmp/", sizeof(full_path));
    strncat(full_path, filename, sizeof(full_path));
    FILE *fp;
    // open file for writing 
    fp = fopen (full_path, "w");
    if (fp == NULL)
    {
        //fprintf(stderr, "\nError opend file\n");
        return;
    }
    fprintf (fp, "%s", dump);
    fclose(fp);
}

/// @cond INTERNAL
/// @addtogroup LunaServiceHubSecurity
/// @{

/**
 * Hash of active service unique name to LSHubPermission
 *
 * Keeps actual permissions for connected services
 */
static GHashTable*
LSHubActivePermissionMapGet()
{
    static GHashTablePointer active_permission_map =
            mk_ptr(g_hash_table_new_full(g_str_hash, g_str_equal, g_free, (GDestroyNotify)LSHubPermissionUnref),
                   g_hash_table_destroy);

    LS_ASSERT(active_permission_map);

    return active_permission_map.get();
}

/// @brief Lookup service permissions from the active permission map
///
/// @param[in] active_service_id  Identification of the service (unique name)
/// @return Permissions if found or nullptr otherwise.
LSHubPermission*
LSHubActivePermissionMapLookup(const char *active_service_id)
{
    if (!active_service_id)
        return nullptr;

    return static_cast<LSHubPermission *>(g_hash_table_lookup(LSHubActivePermissionMapGet(), active_service_id));
}

/// @brief Lookup service permissions from the active permission map
///
/// @param[in] client  Client connection info for identification (unique name)
/// @return Permissions if found or nullptr otherwise.
LSHubPermission*
LSHubActivePermissionMapLookup(const _LSTransportClient *client)
{
    if (!client)
        return nullptr;

    return LSHubActivePermissionMapLookup(_LSTransportClientGetUniqueName(client));
}

/// @brief Add permission info to the active permission map sharing ownership.
///
/// param[in,out]   perm               Permission info
/// param[in]       active_service_id  Key in the active permission map
bool
LSHubActivePermissionMapAddRef(LSHubPermission *perm, const char *active_service_id)
{
    // Look up LSHubPermission for service unique id
    LSHubPermission *found_perm = LSHubActivePermissionMapLookup(active_service_id);

    if (found_perm)
    {
        // Permissions already exist for this active service
        LOG_LS_WARNING(MSGID_LSHUB_ACTIVE_PERMS_EXIST, 1,
            PMLOGKS("SERVICE_ID", active_service_id),
            "Active permissions exist for active service id \"%s\"",
            active_service_id);
        return false;
    }
    else
    {
        // Ref and add permissions for active service
        LSHubPermissionRef(perm);
        g_hash_table_insert(LSHubActivePermissionMapGet(), g_strdup(active_service_id), perm);
    }

    return true;
}

/// @brief Remove active permissions for a given client.
///
/// @param[in] active_service_id Identification of the service (unique name)
/// @return false if was unable to find active permissions
bool
LSHubActivePermissionMapUnref(const char *active_service_id)
{
    if (!active_service_id)
        return false;

    return g_hash_table_remove(LSHubActivePermissionMapGet(), active_service_id);
}

/// @brief Create an entry in the active permission map for a new client
///
/// The function gets permissions for the client from configuration of role files,
/// creates an entry with the given identifier in the active permission map,
/// and caches provided and required security groups related to the client.
///
/// @param[in]  client             The client connection info
/// @param[in]  service_name       The clietn service name
/// @param[in]  active_service_id  Identifier for the record in the map (unique name)
/// @param[out] lserror
/// @return false if failed to query permissions for the client.
bool
LSHubActivePermissionMapClientAdd(const _LSTransportClient *client, const char *service_name,
                                  const char *active_service_id, LSError *lserror)
{
    LS_ASSERT(nullptr != active_service_id);
    const char *lookup_service = service_name;
    // Map anonymous services to empty service name
    if (!lookup_service)
    {
        lookup_service = "";
    }

    if (!_LSTransportClientGetCred(client))
    {
        _LSErrorSet(lserror, MSGID_LSHUB_NO_CLIENT, -1, "Unable to get client credentials");
        return false;
    }

    // First let's assume the service is an "application service", thus look up its
    // permissions by application id.
    const char *permission_key = _LSTransportClientGetApplicationId(client);

    // If the service wasn't an "application service", fall back to the executable path as appId.
    // This will resolve permissions for application containers themselves, binary services etc.
    if (!permission_key)
    {
        permission_key = _LSTransportCredGetExePath(_LSTransportClientGetCred(client));
        if (!permission_key)
        {
            _LSErrorSet(lserror, MSGID_LSHUB_NO_EXE_PATH, -1, "Unable to get client executable path");
            return false;
        }
    }

    auto active_perm = mk_ptr<LSHubPermission>(nullptr, LSHubPermissionUnref);
    LSHubPermission *perm = SecurityData::CurrentSecurityData().permissions.Lookup(lookup_service, permission_key);
    if (perm)
    {
        active_perm.reset(LSHubPermissionNewRef(lookup_service, permission_key));

        if (perm->inbound)
        {
            _LSHubPatternQueueUnref(active_perm->inbound);
            active_perm->inbound = _LSHubPatternQueueCopyRef(perm->inbound);
        }
        if (perm->outbound)
        {
            _LSHubPatternQueueUnref(active_perm->outbound);
            active_perm->outbound = _LSHubPatternQueueCopyRef(perm->outbound);
        }
        active_perm->perm_flags = perm->perm_flags;
        std::string perm_dump = LSHubPermissionDump(perm);
        LOG_LS_DEBUG("%s: perm_dump [%s]", __func__, perm_dump.c_str());
    }
    else
    {
        if (g_conf_security_enabled)
        {
            _LSErrorSet(lserror, MSGID_LSHUB_NO_PERMS_FOR_SERVICE, -1, "Unable to get permissions for service");
            return false;
        }
        LOG_LS_WARNING(MSGID_LSHUB_NO_PERMS_FOR_SERVICE, 1,
                       PMLOGKS("SERVICE_ID", lookup_service),
                       "Unable to get permissions for service");

        active_perm.reset(LSHubPermissionNewRef(lookup_service, permission_key));
    }

    LS_ASSERT(active_perm);

    GroupsMap &groups = SecurityData::CurrentSecurityData().groups;
    // Cache security groups for service life-time in bound LSHubPermission
    LSHubPermissionSetProvided(active_perm.get(), groups.GetProvided(lookup_service));
    LSHubPermissionSetRequired(active_perm.get(), groups.GetRequired(lookup_service));
    LSHubPermissionSetProvidedTrust(active_perm.get(), groups.GetProvidedTrust(lookup_service));
    LSHubPermissionSetRequiredTrust(active_perm.get(), groups.GetRequiredTrust(lookup_service));

    // Add trust level as string
    std::string trust = groups.GetRequiredTrustAsString(lookup_service);
    if (trust.empty())
    {
        LOG_LS_DEBUG("%s: ERRRR !! TRUST IS EMPTY",__func__);
    }
    else
    {
        LOG_LS_DEBUG("%s: SET TRUST to [%s]",__func__, trust.c_str());
        LSHubPermissionSetTrustString(active_perm.get(), trust.c_str());
    }

    if (!LSHubPermissionGetRequired(active_perm.get()).size() && active_perm->perm_flags == NO_BUS_ROLE)
    {
        // If service requires nothing - explicitly add required "public" security group
        LSHubPermissionAddRequired(active_perm.get(), PUBLIC_SECGROUP_NAME);
    }

    if (active_perm->perm_flags & PRIVATE_BUS_ROLE)
    {
        LSHubPermissionAddRequired(active_perm.get(), PRIVATE_SECGROUP_NAME);
    }

    if (active_perm->perm_flags & PUBLIC_BUS_ROLE)
    {
        LSHubPermissionAddRequired(active_perm.get(), PUBLIC_SECGROUP_NAME);
    }
    std::string act_perm_dump = LSHubPermissionDump(active_perm.get());
    DumpToFileActivePerm("act_perm_LSHubActivePermissionMapClientAdd", act_perm_dump.c_str());
    LOG_LS_DEBUG("%s: act_perm_dump [%s]", __func__, act_perm_dump.c_str());
    return LSHubActivePermissionMapAddRef(active_perm.get(), active_service_id);
}

/// @brief Remove active permissions for a given client.
///
/// @param[in]  client The client to get the identification from
/// @param[out] lserror
/// @return false if was unable to find active permissions
bool
LSHubActivePermissionMapClientRemove(const _LSTransportClient *client, LSError *lserror)
{
    LS_ASSERT(client);
    return LSHubActivePermissionMapUnref(_LSTransportClientGetUniqueName(client));
}

/// @} END OF GROUP LunaServiceHubSecurity
/// @endcond
