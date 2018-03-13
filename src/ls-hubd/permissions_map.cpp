// Copyright (c) 2014-2018 LG Electronics, Inc.
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

#include "permissions_map.hpp"

#include <sstream>

#include "error.h"
#include "util.hpp"
#include "pattern.hpp"
#include "permission.hpp"
#include "service_permissions.hpp"
#include "patternqueue.hpp"

/// @cond INTERNAL
/// @addtogroup LunaServiceHubSecurity
/// @{

static bool is_wildcard(const char* str)
{
    return str[strcspn(str, "*?")];
}

void PermissionsMap::Add(PermissionPtr perm)
{
    LSHubServicePermissions *perms = nullptr;
    if (!is_wildcard(perm->service_name))
    {
        // The service name doesn't contain wildcard characters, treat verbatim.

        auto it = _permissions.find(perm->service_name);
        if (it != _permissions.end())
        {
            perms = it->second.get();
        }
        else
        {
            // Try to add new permission
            perms =  LSHubServicePermissionsNewRef(perm->service_name);
            _permissions.emplace(perm->service_name, mk_ptr(perms, LSHubServicePermissionsUnref));
        }
    }
    else
    {
        auto node = _wildcard_permissions.Add(perm->service_name);
        if (!node->perms)
            node->perms.reset(LSHubServicePermissionsNewRef(perm->service_name));
        perms = node->perms.get();
    }

    // Add new permission into service permissions
    LSHubServicePermissionsAddPermissionRef(perms, perm.get());
}

void PermissionsMap::Remove(const char *service_name, const char *id)
{
    if (!is_wildcard(service_name))
    {
        auto it = _permissions.find(service_name);
        if (it != _permissions.end())
        {
            auto perms = it->second.get();
            LSHubServicePermissionsUnrefPermission(perms, id);
            if (!perms->permissions)
                _permissions.erase(it);
        }
    }
    else
    {
        auto action = [id](const char *key, WildcardData &data)
        {
            LSHubServicePermissionsUnrefPermission(data.perms.get(), id);
        };

        _wildcard_permissions.Remove(service_name, action);
    }
}

LSHubPermission* PermissionsMap::Lookup(const char *service_name, const char *id) const
{
    LSHubServicePermissions* perms = LookupServicePermissions(service_name);
    return perms ? LSHubServicePermissionsLookupPermission(perms, id) : nullptr;
}

/// @brief Look up permissions for a given service from role files
///
/// First assume there's an exact service description, then fall back to pattern matching.
///
/// @param[in] service_name  service name to look up
/// @return permissions for the service name or nullptr
LSHubServicePermissions* PermissionsMap::LookupServicePermissions(const char *service_name) const
{
    if (!service_name)
        return nullptr;

    LOG_LS_DEBUG("%s: looking up permissions for service name: \"%s\" in permission map\n", __func__, service_name);

    {
        auto it = _permissions.find(service_name);
        if (it != _permissions.end())
            return it->second.get();
    }

    {
        // We're going to descend searching for our service name.
        // We'll return the deepest wildcard permissions matching our query,
        // thus, by largest preffix.
        LSHubServicePermissions *last_permissions = nullptr;
        auto action = [&last_permissions](const WildcardData &data)
        {
            if (data.perms)
                last_permissions = data.perms.get();
        };

        _wildcard_permissions.Search(service_name, action);
        return last_permissions;
    }

    return nullptr;
}

/// @brief Dump permissions map into a CSV text
///
/// @return Text representation of permission map
std::string PermissionsMap::DumpCsv() const
{
    std::ostringstream oss;

    auto dump_entry = [&oss](const std::string &name, const char *suffix, const LSHubServicePermissions *perms)
    {
        for (GSList *l = perms->permissions; l; l = l->next)
        {
            const LSHubPermission *perm = static_cast<const LSHubPermission *>(l->data);

            // Tag
            oss << "Perms," << name << suffix;

            // Service name
            oss << ',' << perm->service_name;
            // Executable for which the role file was
            oss << ',' << perm->exe_path;
            // List of inbound services
            oss << ',' << _LSHubPatternQueueDumpPlain(perm->inbound);
            // List of outbound services
            oss << ',' << _LSHubPatternQueueDumpPlain(perm->outbound);
            oss << '\n';
        }
    };

    for (const auto &entry : _permissions)
    {
        dump_entry(entry.first, "", entry.second.get());
    }

    auto action = [&](const std::string &prefix, const WildcardData &data)
    {
        if (data.perms)
            dump_entry(prefix, "*", data.perms.get());
    };

    _wildcard_permissions.Visit(action);

    return oss.str();
}

/// @} END OF GROUP LunaServiceHubSecurity
/// @endcond
