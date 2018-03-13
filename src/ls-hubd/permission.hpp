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

#ifndef _PERMISION_HPP_
#define _PERMISION_HPP_

#include <set>
#include <string>
#include <algorithm>
#include <unordered_map>

#include <pbnjson.hpp>

struct LSError;
struct LSHubPermission;
struct LSTransportClient;
struct _LSHubPatternQueue;

typedef struct LSError LSError;
typedef struct LSHubPermission LSHubPermission;
typedef struct LSTransportClient _LSTransportClient;
typedef struct _LSHubPatternQueue _LSHubPatternQueue;

/// @cond INTERNAL
/// @addtogroup LunaServiceHubSecurity
/// @{

/// Array of unsorted groups (whether required or provided)
/// We will be interning group names, thus, pointers are enough.

class Groups : public std::vector<const char *>
{
    typedef std::vector<const char *> Base;

public:
    Groups() = default;
    Groups(std::initializer_list<const char*> l)
        : Base(l)
    {}

    void insert(const Groups &other)
    {
        Base::insert(begin(), other.begin(), other.end());
    }

    void erase(const char *group)
    {
        Base::erase(std::find(begin(), end(), group));
    }

    bool operator== (const Groups& other) const
    {
        if (this == &other) return true;
        if (size() != other.size()) return false;

        std::vector<value_type> lhs(*this), rhs(other);
        std::sort(lhs.begin(), lhs.end());
        std::sort(rhs.begin(), rhs.end());

        return std::equal(lhs.begin(), lhs.end(), rhs.begin());
    }
};

/// Map of category pattern to set of provided groups
typedef std::unordered_map<std::string, Groups> CategoryMap;

/// Permission data (section #/permissions/* from role files)
struct LSHubPermission {
    int ref;                      //< Reference count
    const char *service_name;     //< Service name (exact if effective, pattern from role file)
    const char *exe_path;         //< Executable full path for authentication
    _LSHubPatternQueue *inbound;  //< List of allowed inbound service patterns
    _LSHubPatternQueue *outbound; //< List of allowed outbound service patterns
    Groups requires;              //< Set of required access control groups (ACG)
    CategoryMap provides;         //< Map of category patterns to their provided ACG
    uint32_t perm_flags;          //< Flag of permission origin (new vs legacy, private vs public)
    pbnjson::JValue version;      //< Service API version
};

typedef std::unique_ptr<LSHubPermission, bool(*)(LSHubPermission*)> PermissionPtr;
typedef std::vector<PermissionPtr> PermissionArray;

LSHubPermission*
LSHubPermissionNew(raw_buffer service_name, const char *exe_path);

LSHubPermission*
LSHubPermissionNew(const std::string &service_name, const char *exe_path);

LSHubPermission*
LSHubPermissionNewRef(raw_buffer service_name, const char *exe_path);

LSHubPermission*
LSHubPermissionNewRef(const std::string &service_name, const char *exe_path);

void
LSHubPermissionRef(LSHubPermission *perm);

bool
LSHubPermissionUnref(LSHubPermission *perm);

void
LSHubPermissionFree(LSHubPermission *perm);

void
LSHubPermissionPrint(const LSHubPermission *perm, FILE *file);

std::string
LSHubPermissionRequiresToString(const LSHubPermission *perm);

std::string
LSHubPermissionProvidesToString(const LSHubPermission* perm);

std::string
LSHubPermissionDump(const LSHubPermission *perm);

void
LSHubPermissionAddAllowedInbound(LSHubPermission *perm, const char *name);

void
LSHubPermissionAddAllowedOutbound(LSHubPermission *perm, const char *name);

/// @brief Access permission flags (legacy vs new, private vs public)
/// @param[in] perm
static inline uint32_t
LSHubPermissionGetFlags(const LSHubPermission *perm)
{
    return perm->perm_flags;
}

/// @brief Access required groups
/// @param[in] perm
static inline const Groups&
LSHubPermissionGetRequired(const LSHubPermission *perm)
{
    return perm->requires;
}

/// @brief Access category map to provided groups
/// @param[in] perm
static inline const CategoryMap&
LSHubPermissionGetProvided(const LSHubPermission *perm)
{
    return perm->provides;
}

static inline const pbnjson::JValue &
LSHubPermissionGetAPIVersion(LSHubPermission *perm)
{
    return perm->version;
}

static inline void
LSHubPermissionSetRequired(LSHubPermission *perm, const Groups& requires)
{
    perm->requires = requires;
}

static inline void
LSHubPermissionSetProvided(LSHubPermission *perm, const CategoryMap& provides)
{
    perm->provides = provides;
}

static inline void
LSHubPermissionSetAPIVersion(LSHubPermission *perm, const pbnjson::JValue &version)
{
    perm->version = version;
}

bool
LSHubPermissionAddRequired(LSHubPermission *perm, const char *group_name);

bool
LSHubPermissionAddProvided(LSHubPermission *perm, const char *category_name, const char *group_name);

bool
LSHubPermissionIsEqual(const LSHubPermission *a, const LSHubPermission *b);

void
LSHubPermissionMergePermissions(LSHubPermission *to, const LSHubPermission *from);

void
LSHubPermissionMergePermissionsAllowDups(LSHubPermission *to, const LSHubPermission *from);

void
LSHubPermissionRemovePermissions(LSHubPermission *from, const LSHubPermission *what);

/// @} END OF GROUP LunaServiceHubSecurity
/// @endcond

#endif //_PERMISION_HPP_
