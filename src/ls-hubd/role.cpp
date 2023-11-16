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

#include "role.hpp"

#include "error.h"
#include "pattern.hpp"
#include "role_map.hpp"
#include "patternqueue.hpp"
#include "simple_pbnjson.h"

/// @cond INTERNAL
/// @addtogroup LunaServiceHubSecurity
/// @{

#define ROLE_TYPE_DEVMODE       "devmode"       // Can only call method allowed by devmode certificate
#define ROLE_TYPE_REGULAR       "regular"       // Complies with ACG
#define ROLE_TYPE_PRIVILEGED    "privileged"    // Can push roles and send with application id
#define ROLE_TYPE_PROXY         "proxy"         // indirect call

/// @brief Create new role for given executable
///
/// @param[in] id Full path to the executable or appID
/// @param[in] type
/// @param[in] role_flags
/// @return New instance of role
LSHubRole*
LSHubRoleNew(const std::string &id, LSHubRoleType type, uint32_t role_flags)
{
    LOG_LS_DEBUG("%s: Create role id: \"%s\", type: %d\n", __func__, id.c_str(), type);
    LSHubRole *role = new LSHubRole();

    role->id = id;
    role->type = static_cast<uint32_t>(type);
    role->allowed_names = _LSHubPatternQueueNewRef();
    role->role_flags = role_flags;

    return role;
}

void
LSHubRoleFree(LSHubRole *role)
{
    LS_ASSERT(role != NULL);
    LOG_LS_DEBUG("%s\n", __func__);

    _LSHubPatternQueueUnref(role->allowed_names);

    delete role;
}

/* creates a copy of a HubRole with refcount of 1 */
LSHubRole*
LSHubRoleCopyRef(const LSHubRole *role)
{
    LOG_LS_DEBUG("%s id=\"%s\"\n", __func__, role->id.c_str());

    LSHubRole *new_role = LSHubRoleNew(role->id, LSHubRoleTypeInvalid, role->role_flags);
    new_role->type = role->type;
    new_role->ref = 1;

    /* Unref the queue allocated in LSHubRoleNew */
    _LSHubPatternQueueUnref(new_role->allowed_names);

    /* shallow copy */
    new_role->allowed_names = _LSHubPatternQueueCopyRef(role->allowed_names);

    new_role->flags = role->flags;

    return new_role;
}

void
LSHubRoleAddAllowedName(LSHubRole *role, const char *name, uint32_t flags)
{
    LS_ASSERT(role != NULL);
    LS_ASSERT(name != NULL);

    LOG_LS_DEBUG("%s: Role \"%s\" add name: \"%s\"\n", __func__, role->id.c_str(), name);

    _LSHubPatternSpec *pattern = _LSHubPatternSpecNewRef(name);

    _LSHubPatternQueueInsertSorted(role->allowed_names, pattern); /* increments ref count */
    _LSHubPatternSpecUnref(pattern);

    role->flags[name] |= flags;
}

/// @brief Dump escaped allowed names
/// @param[in] role
/// @return string
std::string
LSHubRoleAllowedNamesDump(const LSHubRole *role)
{
    std::string ret;
    if (LIKELY(role))
    {
        const char *sep = "";
        const _LSHubPatternQueue * q = role->allowed_names;
        LS_ASSERT(q != NULL);

        for (GSList *list = q->q; list; list = g_slist_next(list))
        {
            _LSHubPatternSpec *pattern = static_cast<_LSHubPatternSpec*>(list->data);
            if (pattern->pattern_str)
            {
                ret = ret + sep + "\"" + pattern->pattern_str + "\"";
                sep = ", ";
            }
        }
    }

    return ret;
}

/// @brief Dump role type and allowed names into a plain text list
/// @param[in] role
/// @return string
std::string
LSHubRoleDumpPlain(const LSHubRole *role)
{
    std::string dump;

    // Role type
    if ((role->type & LSHubRoleTypeRegular))
        dump += 'r';
    if ((role->type & LSHubRoleTypePrivileged))
        dump += 'p';
    if ((role->type & LSHubRoleTypePrivilegedPublic))
        dump += 'P';
    if ((role->type & LSHubRoleTypeDevmode))
        dump += 'd';

    // allowedNames
    dump += ',';
    dump += _LSHubPatternQueueDumpPlain(role->allowed_names);

    return dump;
}

void
LSHubRolePrint(const LSHubRole *role, FILE *file)
{
    fprintf(file, "Role: ref: %d, id: \"%s\", type: %d, role_flags: %d ",
                   role->ref, role->id.c_str(), role->type, role->role_flags);
    fprintf(file, "allowed_names: ");
    _LSHubPatternQueuePrint(role->allowed_names, file);
    fprintf(file, "flags: ");
    for (const auto &v: role->flags)
    {
        fprintf(file, "%s: %d ", v.first.c_str(), v.second);
    }
    fprintf(file, "\n");
}

/// @brief Merge same executable role flags obtained from public
///        and private legacy role files
///
/// @param[in,out]  to
/// @param[in]      from
void
LSHubRoleMergeFlags(LSHubRole *to, const LSHubRole *from)
{
    LS_ASSERT(to != NULL);
    LS_ASSERT(from != NULL);

    for (const auto &v: from->flags)
        to->flags[v.first] |= v.second;

    to->role_flags |= from->role_flags;
    to->type |= from->type;
}

/// @brief Revoke some privileges from a role
///
/// @param[in,out]  role      Role to modify
/// @param[in]      bus_flag  The flag to unset
void
LSHubRoleDropBusFlag(LSHubRole *role, BusTypeRoleFlag bus_flag)
{
    LS_ASSERT(role != NULL);

    for (auto &v: role->flags)
        v.second &= ~bus_flag;
}

/// @brief Merge same executable allowed names obtained from public
///        and private legacy role files
///
/// @param[in,out]  to
/// @param[in]      from
void
LSHubRoleMergeAllowedNames(LSHubRole *to, const LSHubRole*from)
{
    LS_ASSERT(to != NULL);
    LS_ASSERT(from != NULL);

    _LSHubPatternQueueMergeInto(to->allowed_names, from->allowed_names);
}

bool
LSHubRoleIsNameAllowed(const LSHubRole *role, const char* name)
{
    LS_ASSERT(role != NULL);

    /* un-named services are represented as empty strings in the map */
    if (name == NULL)
    {
        name = "";
    }
    else if (name[0] == '\0')
    {
        /* empty strings are not allowed as service names */
        return false;
    }

    return _LSHubPatternQueueHasMatch(role->allowed_names, name);
}

/// @brief Compare for equality two roles
///
/// @param[in]  a, b
/// @return true if a equals b
bool
LSHubRoleIsEqualAllowedNames(const LSHubRole *a, const LSHubRole *b)
{
    LS_ASSERT(a != NULL);
    LS_ASSERT(b != NULL);

    if (a == b)
        return true;

    return a->id == b->id && _LSHubPatternQueueIsEqual(a->allowed_names, b->allowed_names);
}

/// @brief Find service flags by service name
///
/// Scan allowed names to match the service name. If exact match found,
/// return its flags. Otherwise accumulate flags for every matching
/// allowed name.
///
/// @param[in] role          Role information
/// @param[in] service_name  Service name to query
/// @return bit mask of service flags (refer to BusTypeRoleFlag)
static uint32_t
LSHubRoleGetServiceFlags(const LSHubRole *role, const char *service_name)
{
    /* un-named service name is mapped to empty string*/
    if (nullptr == service_name)
    {
        service_name = "";
    }

    auto it = role->flags.find(service_name);
    if (it != role->flags.end())
        return it->second;

    if (!g_utf8_validate(service_name, -1, NULL))
        return 0;

    uint32_t ret(0);
    for (const auto& v: role->flags)
    {
        if (std::string::npos == v.first.find_first_of("*?"))
            continue;
        if (!g_utf8_validate(v.first.c_str(), -1, NULL))
            continue;
        if (g_pattern_match_simple(v.first.c_str(), service_name))
            ret |= v.second;
    }

    return ret;
}

/// @brief Is the service allowed to register in the legacy group "private"?
bool
LSHubRoleIsPrivateAllowed(const LSHubRole *role, const char *service_name)
{
    LS_ASSERT(role != NULL);

    if (!LSHubRoleIsOldFormat(role))
        return false;

    return (LSHubRoleGetServiceFlags(role, service_name) & PRIVATE_BUS_ROLE);
}

/// @brief Is the service allowed to register in the legacy group "public"?
bool
LSHubRoleIsPublicAllowed(const LSHubRole *role, const char *service_name)
{
    LS_ASSERT(role != NULL);

    if (!LSHubRoleIsOldFormat(role))
        return false;

    return (LSHubRoleGetServiceFlags(role, service_name) & PUBLIC_BUS_ROLE);
}

/// @brief Does the role allow privileged requests (mocking other services)?
bool
LSHubRoleIsPrivileged(const LSHubRole *role, BusTypeRoleFlag bus_flag)
{
    LS_ASSERT(role != NULL);

    if (bus_flag & PUBLIC_BUS_ROLE)
        return (role->type & LSHubRoleTypePrivilegedPublic);
    else if (bus_flag & PRIVATE_BUS_ROLE)
        return (role->type & LSHubRoleTypePrivileged);
    else
        return (role->type & LSHubRoleTypePrivileged ||
            role->type & LSHubRoleTypePrivilegedPublic);
}

bool LSHubRoleIsProxy(const LSHubRole *role) {
    LS_ASSERT(role != NULL);
    return (role->type & LSHubRoleTypeProxy);
}

LSHubRoleType
_LSHubRoleTypeStringToType(const std::string &type, uint32_t flags)
{
    return _LSHubRoleTypeStringToType(raw_buffer{type.data(), type.size()}, flags);
}

LSHubRoleType
_LSHubRoleTypeStringToType(raw_buffer type, uint32_t flags)
{
    LOG_LS_DEBUG("%s: type: \"%.*s\"\n", __func__, (int)type.m_len, type.m_str);

    if (buffer_eq_cstr(type, ROLE_TYPE_REGULAR))
    {
        return LSHubRoleTypeRegular;
    }
    else if (buffer_eq_cstr(type, ROLE_TYPE_DEVMODE))
    {
        return LSHubRoleTypeDevmode;
    }
    else if (buffer_eq_cstr(type, ROLE_TYPE_PRIVILEGED))
    {
        return (flags & PUBLIC_BUS_ROLE) ? LSHubRoleTypePrivilegedPublic : LSHubRoleTypePrivileged;
    }
    else if (buffer_eq_cstr(type, ROLE_TYPE_PROXY))
    {
        return LSHubRoleTypeProxy;
    }
    else
    {
        return LSHubRoleTypeInvalid;
    }
}

/// @} END OF GROUP LunaServiceHubSecurity
/// @endcond
