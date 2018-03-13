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

#include "service_permissions.hpp"

#include <glib.h>

#include "error.h"
#include "conf.hpp"
#include "permission.hpp"

/// @cond INTERNAL
/// @addtogroup LunaServiceHubSecurity
/// @{

LSHubServicePermissions*
LSHubServicePermissionsNew(const char *service_name)
{
   LSHubServicePermissions *perms = g_slice_new0(LSHubServicePermissions);
   perms->default_permission = LSHubPermissionNew(service_name, nullptr);
   return perms;
}

LSHubServicePermissions*
LSHubServicePermissionsNewRef(const char *service_name)
{
    LOG_LS_DEBUG("%s\n", __func__);

    LSHubServicePermissions *perms = LSHubServicePermissionsNew(service_name);

    if (perms)
    {
        perms->ref = 1;
    }

    return perms;
}

void
LSHubServicePermissionsUnref(LSHubServicePermissions *perms)
{
    LS_ASSERT(perms != NULL);
    LS_ASSERT(g_atomic_int_get(&perms->ref) > 0);

    if (g_atomic_int_dec_and_test(&perms->ref))
    {
        LSHubServicePermissionsFree(perms);
    }
}

static void
FreePermission(gpointer data)
{
    LSHubPermissionUnref(reinterpret_cast<LSHubPermission *>(data));
}

void
LSHubServicePermissionsFree(LSHubServicePermissions *perms)
{
    LS_ASSERT(perms != NULL);

    g_slist_free_full(perms->permissions, &FreePermission);
    LSHubPermissionFree(perms->default_permission);
    g_slice_free(LSHubServicePermissions, perms);
}

void
LSHubServicePermissionsAddPermissionRef(LSHubServicePermissions *perms, LSHubPermission *perm)
{
    LOG_LS_DEBUG("%s: attempting to add permission %p to permission map...\n", __func__, perm);
    /* Check if permission for service_name and exe_path exists
     * if yes - set error (permissions differ) or print debug (permissions match), use LSHubPermissionIsEqual
     * if no - prepend passed LSHubPermission into list
     * Check if default permission exists - if no copy passed permission and set it as default
     */
    LSHubPermission *found_perm = NULL;
    GSList *list = perms->permissions;
    while (list)
    {
        LSHubPermission *curr = (LSHubPermission *)list->data;
        // Check for existing permission
        if (!g_strcmp0(curr->exe_path, perm->exe_path))
        {
            found_perm = curr;
            break;
        }

        list = g_slist_next(list);
    }

    // Existing permission found - report error if differs
    if (found_perm)
    {
        /* Permissions are global, so they can't be duplicated.
         * However, there's no point to complain on *equal* duplicates.
         * And we need to merge permissions from public/private role files
         */
        if (LSHubPermissionIsEqual(perm, found_perm))
        {
            found_perm->perm_flags |= perm->perm_flags;
            LOG_LS_DEBUG("Allowing duplicate service name in permission map: \"%s\"", perm->service_name);
            return;
        }

        std::string perm_str = LSHubPermissionDump(perm);
        std::string found_perm_str = LSHubPermissionDump(found_perm);

        if ((found_perm->perm_flags == PRIVATE_BUS_ROLE && perm->perm_flags == PUBLIC_BUS_ROLE) ||
            (found_perm->perm_flags == PUBLIC_BUS_ROLE && perm->perm_flags == PRIVATE_BUS_ROLE))
        {
            // Need to merge permissions from public/private role files
            found_perm->perm_flags |= perm->perm_flags;
            LSHubPermissionMergePermissions(found_perm, perm);

            LSHubPermissionMergePermissions(perms->default_permission, perm);
            perms->default_permission->perm_flags |= perm->perm_flags;

            LOG_LS_WARNING(MSGID_LSHUB_SERVICE_EXISTS, 0,
                    "Found different permissions in private/public roles: %s vs %s",
                    perm_str.c_str(), found_perm_str.c_str());
        }
        else
        {
            LOG_LS_WARNING(MSGID_LSHUB_SERVICE_EXISTS, 0,
                    "Skipping duplicate service name to permission map: %s (already there %s)",
                    perm_str.c_str(), found_perm_str.c_str());
        }

        LOG_LS_DEBUG("%s: failure\n", __func__);
        return;
    }

    // Prepend permission to list
    LSHubPermissionRef(perm);
    perms->permissions = g_slist_prepend(perms->permissions, perm);

    // Merge permission in/out bounds and flags to default permission
    LSHubPermissionMergePermissionsAllowDups(perms->default_permission, perm);
    perms->default_permission->perm_flags |= perm->perm_flags;

    LOG_LS_DEBUG("%s: success\n", __func__);
}

void
LSHubServicePermissionsUnrefPermission(LSHubServicePermissions *perms, const char* exe_path)
{
    LSHubPermission *found = nullptr;
    for (GSList *list = perms->permissions; list; list = g_slist_next(list))
    {
        LSHubPermission *curr = (LSHubPermission *)list->data;
        if (g_strcmp0(curr->exe_path, exe_path) == 0)
        {
            found = curr;
        }
    }

    if (found)
    {
        LSHubPermissionRemovePermissions(perms->default_permission, found);

        perms->permissions = g_slist_remove(perms->permissions, found);
        LSHubPermissionUnref(found);
    }
}

/// @brief Find permissions for a given executable
///
/// If executable isn't given, default permissions are returned (first initialized).
///
/// @param[in] perms
/// @param[in] exe_path
/// @return Found permissions
LSHubPermission*
LSHubServicePermissionsLookupPermission(const LSHubServicePermissions *perms, const char *exe_path)
{
    if (!exe_path)
    {
        return perms->default_permission;
    }

    LSHubPermission *found_perm = NULL;
    GSList *list = perms->permissions;
    while (list)
    {
        LSHubPermission *curr = (LSHubPermission *)list->data;
        // Check for existing permission
        if (!g_strcmp0(curr->exe_path, exe_path))
        {
            found_perm = curr;
            break;
        }

        list = g_slist_next(list);
    }

    if (found_perm)
        return found_perm;

    const char *name = perms->default_permission ? perms->default_permission->service_name : "(null)";
    LOG_LS_WARNING(MSGID_LSHUB_ROLE_FILE_ERR, 0,
            "Can not find service \"%s\" permissions for executable \"%s\"", name, exe_path);

    return perms->default_permission;
}

/// @} END OF GROUP LunaServiceHubSecurity
/// @endcond
