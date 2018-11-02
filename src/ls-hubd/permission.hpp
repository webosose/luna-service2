// Copyright (c) 2008-2019 LG Electronics, Inc.
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
#include "log.h"

struct LSError;
struct LSHubPermission;
struct LSTransportClient;
struct _LSHubPatternQueue;

typedef struct LSError LSError;
typedef struct LSHubPermission LSHubPermission;
typedef struct LSTransportClient _LSTransportClient;
typedef struct _LSHubPatternQueue _LSHubPatternQueue;
#define DEFAULT_TRUST_LEVEL "dev"

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

class TrustLevel : public std::vector<const char *>
{
    typedef std::vector<const char *> Base;

public:
    TrustLevel() = default;
    TrustLevel(std::initializer_list<const char*> l)
        : Base(l)
    {}

    void insert(const TrustLevel &other)
    {
        Base::insert(begin(), other.begin(), other.end());
    }

    void erase(const char *trust_level)
    {
        Base::erase(std::find(begin(), end(), trust_level));
    }

    bool operator== (const TrustLevel& other) const
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
/// Map of group to its trust level
typedef std::unordered_map<std::string, TrustLevel> TrustMap;
/// Map of services to its groups and their corresponding trusts
typedef std::unordered_map<std::string, TrustMap> ServiceToTrustMap;

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
    const char *required_trust;        // < String containing required trust
    TrustMap trust_level_required;          // < Map of groups to their required trust level
    TrustMap trust_level_provided;          // < Map of groups to their provided trust level

    LSHubPermission() { required_trust = nullptr; }
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

static inline const std::string
LSHubPermissionGetServiceName(const LSHubPermission *perm)
{
    return std::string(perm->service_name);
}

/// @brief Access category map to provided groups
/// @param[in] perm
static inline const CategoryMap&
LSHubPermissionGetProvided(const LSHubPermission *perm)
{
    return perm->provides;
}

static inline const TrustMap&
LSHubPermissionGetProvidedTrust(const LSHubPermission *perm)
{
    return perm->trust_level_provided;
}

static inline const TrustMap&
LSHubPermissionGetRequiredTrust(const LSHubPermission *perm)
{
    return perm->trust_level_required;
}

static inline const char*
LSHubPermissionGetRequiredTrustAsString(const LSHubPermission *perm)
{
    // We can return first groups trust as this is a map of
    // trustlevel from application to its required groups.
    // Hence all required groups will have same trust level
    LOG_LS_DEBUG("NILESH >>>> %s :get perm level perm->required_trust %s", __func__, perm->required_trust);
    return perm->required_trust;
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
LSHubPermissionSetProvidedTrust(LSHubPermission *perm, const TrustMap& trust_level)
{
    perm->trust_level_provided = trust_level;
}

static inline void
LSHubPermissionSetRequiredTrust(LSHubPermission *perm, const TrustMap& trust_level)
{
    perm->trust_level_required = trust_level;
}

static inline void
LSHubPermissionSetTrustString(LSHubPermission *perm, const char* trust_level)
{
    if (trust_level)
        perm->required_trust = g_strdup(trust_level);
    else
        perm->required_trust = g_strdup(DEFAULT_TRUST_LEVEL);
    LOG_LS_DEBUG("NILESH >>>> %s :set perm level perm->required_trust %s", __func__, perm->required_trust);
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
LSHubPermissionAddTrust(LSHubPermission *perm, const char *group_name, const char *trust_level);

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
