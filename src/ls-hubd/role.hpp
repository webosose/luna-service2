// Copyright (c) 2008-2021 LG Electronics, Inc.
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

#ifndef _ROLE_HPP_
#define _ROLE_HPP_

#include <map>
#include <string>
#include <cstdio>

#include <pbnjson.h>

#include "error.h"
#include "conf.hpp"

struct _LSHubPatternQueue;
typedef struct _LSHubPatternQueue _LSHubPatternQueue;

/// @cond INTERNAL
/// @addtogroup LunaServiceHubSecurity
/// @{

/// @brief Privilege type of the executable. Privileged executable are allowed
///        to disguise services.
typedef enum {
    LSHubRoleTypeInvalid            = 0,  //< Trap
    LSHubRoleTypeRegular            = 1,  //< Regular non-privileged
    LSHubRoleTypePrivileged         = 2,  //< Privileged (whether new or legacy private)
    LSHubRoleTypePrivilegedPublic   = 4,  //< Privileged legacy public
    LSHubRoleTypeDevmode            = 8,  //< Restricted to the API described in the devmode certificate
    LSHubRoleTypeProxy              = 16, //< proxy type
} LSHubRoleType;

/// @brief Executable allowed roles
struct LSHubRole {
    int ref;                                //< Reference count
    std::string id;                         //< ID - path to the executable or appId for authentication
    uint32_t type;                          //< See LSHubRoleType
    _LSHubPatternQueue *allowed_names;      //< List of allowed service names
    uint32_t role_flags;                    //< Privilege flags
    std::map<std::string, uint32_t> flags;  //< Effective flags for registered services
};

typedef std::unique_ptr<LSHubRole, bool(*)(LSHubRole*)> RolePtr;

LSHubRole*
LSHubRoleNew(const std::string &id, LSHubRoleType type, uint32_t role_flags = NO_BUS_ROLE);

static inline LSHubRole*
LSHubRoleNewRef(const std::string &id, LSHubRoleType type, uint32_t role_flags = NO_BUS_ROLE)
{
    LOG_LS_DEBUG("%s: id: \"%s\", type: %d\n", __func__, id.c_str(), type);
    LSHubRole *role = LSHubRoleNew(id, type, role_flags);

    role->ref = 1;

    return role;
}

static inline void
LSHubRoleRef(LSHubRole *role)
{
    LS_ASSERT(role != NULL);
    LS_ASSERT(g_atomic_int_get(&role->ref) > 0);

    LOG_LS_DEBUG("%s\n", __func__);

    g_atomic_int_inc(&role->ref);
}

void
LSHubRoleFree(LSHubRole *role);

/* returns true if the ref count went to 0 and the role was freed */
static inline bool
LSHubRoleUnref(LSHubRole *role)
{
    LS_ASSERT(role != NULL);
    LS_ASSERT(g_atomic_int_get(&role->ref) > 0);

    LOG_LS_DEBUG("%s\n", __func__);

    if (g_atomic_int_dec_and_test(&role->ref))
    {
        LSHubRoleFree(role);
        return true;
    }

    return false;
}

/* creates a copy of a HubRole with refcount of 1 */
LSHubRole*
LSHubRoleCopyRef(const LSHubRole *role);

void
LSHubRoleAddAllowedName(LSHubRole *role, const char *name, uint32_t flags = 0);

std::string
LSHubRoleAllowedNamesDump(const LSHubRole *role);

std::string
LSHubRoleDumpPlain(const LSHubRole *role);

void
LSHubRolePrint(const LSHubRole *role, FILE *file);

void
LSHubRoleMergeFlags(LSHubRole *to, const LSHubRole *from);

void
LSHubRoleDropBusFlag(LSHubRole *role, BusTypeRoleFlag bus_flag);

void
LSHubRoleMergeAllowedNames(LSHubRole *to, const LSHubRole *from);

bool
LSHubRoleIsNameAllowed(const LSHubRole *role, const char* name);

bool
LSHubRoleIsEqualAllowedNames(const LSHubRole *a, const LSHubRole *b);

static inline uint32_t
LSHubRoleGetFlags(const LSHubRole *role)
{
    LS_ASSERT(role != NULL);
    return role->role_flags;
}

/// @brief Determine if role came from either legacy role files
///
/// @param[in] role
/// return
static inline bool
LSHubRoleIsOldFormat(const LSHubRole *role)
{
    return (NO_BUS_ROLE != LSHubRoleGetFlags(role));
}

bool
LSHubRoleIsPrivateAllowed(const LSHubRole *role, const char *service_name);

bool
LSHubRoleIsPublicAllowed(const LSHubRole *role, const char *service_name);

bool
LSHubRoleIsPrivileged(const LSHubRole *role, BusTypeRoleFlag bus_flag);

bool LSHubRoleIsProxy(const LSHubRole *role);

inline LSHubRoleType
LSHubRoleGetType(const LSHubRole *role)
{
    return LSHubRoleType(role->type);
}

LSHubRoleType
_LSHubRoleTypeStringToType(const std::string &type, uint32_t flags = NO_BUS_ROLE);

LSHubRoleType
_LSHubRoleTypeStringToType(raw_buffer type, uint32_t flags = NO_BUS_ROLE);

/// @} END OF GROUP LunaServiceHubSecurity
/// @endcond

#endif //_ROLE_HPP_
