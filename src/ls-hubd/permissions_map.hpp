// Copyright (c) 2015-2018 LG Electronics, Inc.
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

#ifndef _PERMISSIONS_MAP_HPP_
#define _PERMISSIONS_MAP_HPP_

#include <unordered_map>

#include "pattern.hpp"
#include "permission.hpp"
#include "service_permissions.hpp"
#include "trie.hpp"

class PermissionsMap
{

public:
    PermissionsMap() = default;

    PermissionsMap(const PermissionsMap&) = delete;
    PermissionsMap& operator=(const PermissionsMap&) = delete;
    PermissionsMap(PermissionsMap&&) = default;
    PermissionsMap& operator=(PermissionsMap&&) = default;

    void Add(PermissionPtr perm);
    void Remove(const char *service_name, const char *exe_path);

    LSHubPermission* Lookup(const char *service_name, const char *id) const;
    LSHubServicePermissions* LookupServicePermissions(const char *service_name) const;

    std::string DumpCsv() const;

private:
    std::unordered_map<std::string, PermissionsPtr> _permissions;

    struct WildcardData
    {
        PermissionsPtr perms;

        bool IsEmpty() const { return !perms || !perms->permissions; }

        WildcardData(): perms(nullptr, LSHubServicePermissionsUnref) {}
    };

    Trie<WildcardData> _wildcard_permissions;
};

#endif //_PERMISSIONS_MAP_HPP_
