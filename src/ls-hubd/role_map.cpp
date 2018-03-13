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

#include "role_map.hpp"

#include <sstream>

#include "role.hpp"
#include "error.h"
#include "pattern.hpp"
#include "patternqueue.hpp"

/// @cond INTERNAL
/// @addtogroup LunaServiceHubSecurity
/// @{

void RoleMap::Add(RolePtr role)
{
    LOG_LS_DEBUG("%s: ref role: %p in role map...\n", __func__, role.get());

    /* check to see if it already exists -- we don't want duplicates */
    auto found = _roles.find(role->id);
    if (found == _roles.end())
    {
        _roles.emplace(role->id, std::move(role));
        return;
    }

    LSHubRole *found_role = found->second.get();
    if ((LSHubRoleGetFlags(found_role) == PUBLIC_BUS_ROLE && LSHubRoleGetFlags(role.get()) == PRIVATE_BUS_ROLE)
        || (LSHubRoleGetFlags(found_role) == PRIVATE_BUS_ROLE && LSHubRoleGetFlags(role.get()) == PUBLIC_BUS_ROLE))
    {
        if (!LSHubRoleIsEqualAllowedNames(found_role, role.get()))
        {
            std::string names_str = LSHubRoleAllowedNamesDump(role.get());
            std::string found_names_str = LSHubRoleAllowedNamesDump(found_role);
            LOG_LS_DEBUG("Found different allowed names in private/public roles for '%s': '%s' vs '%s'",
                         role->id.c_str(), names_str.c_str(), found_names_str.c_str());

            LSHubRoleMergeAllowedNames(found_role, role.get());
        }
        LSHubRoleMergeFlags(found_role, role.get());
    }
    else
    {
        LOG_LS_WARNING(MSGID_LSHUB_ROLE_EXISTS, 0, "Role already exists for id: \"%s\"", role->id.c_str());
    }
}

void RoleMap::Remove(const std::string &key)
{
    LOG_LS_DEBUG("%s: removing role: \"%s\" from role map...\n", __func__, key.c_str());
    _roles.erase(key);
}

const LSHubRole* RoleMap::Lookup(const std::string &key) const
{
    LOG_LS_DEBUG("%s: look up role by role key: \"%s\" in role map\n", __func__, key.c_str());

    auto found = _roles.find(key);
    return found != _roles.end() ? found->second.get() : nullptr;
}

std::string RoleMap::DumpCsv() const
{
    std::ostringstream oss;

    for (const auto &entry : _roles)
    {
        // Exe/appId
        oss << "Role," << entry.first;
        // Role
        oss << ',' << LSHubRoleDumpPlain(entry.second.get());
        oss << '\n';
    }

    return oss.str();
}

/// @} END OF GROUP LunaServiceHubSecurity
/// @endcond
