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

#include "permission.hpp"

#include <sstream>

#include "error.h"
#include "util.hpp"
#include "conf.hpp"
#include "transport.h"
#include "pattern.hpp"
#include "patternqueue.hpp"
#include "permissions_map.hpp"
#include "active_permission_map.hpp"


/// @cond INTERNAL
/// @addtogroup LunaServiceHubSecurity
/// @{

static std::string
_LSHubGroupsToString(const Groups& s)
{
    std::stringstream ss;

    ss << "[";
    if (!s.empty())
    {
        auto it = s.begin();
        ss << "\"" << *it << "\"";
        for (++it; it != s.end(); ++it)
        {
            ss << ", \"" << *it << "\"";
        }
    }
    ss << "]";

    return  ss.str();
}

static std::string
_LSHubTrustLevelsToString(const TrustLevel& s)
{
    std::stringstream ss;

    ss << "[";
    if (!s.empty())
    {
        auto it = s.begin();
        ss << "\"" << *it << "\"";
        for (++it; it != s.end(); ++it)
        {
            ss << ", \"" << *it << "\"";
        }
    }
    ss << "]";

    return  ss.str();
}

//std::string
//LSHubPermissionTrustLevelsToString(const LSHubPermission* perm)
//{
//    return _LSHubTrustLevelsToString(perm->trustLevel);
//}

std::string
LSHubPermissionRequiresToString(const LSHubPermission* perm)
{
    return _LSHubGroupsToString(perm->requires);
}

std::string
LSHubPermissionRequiredTrustLevelsToString(const LSHubPermission* perm)
{
    LOG_LS_DEBUG("%s\n", __func__);

    const TrustMap& cm = perm->trust_level_required;

    std::stringstream ss;

    ss << "{";
    if (!cm.empty())
    {
        for (auto it = cm.begin(); it != cm.end(); ++it)
        {
            const std::string &key = it->first;
            const auto &value = it->second;

            if (it != cm.begin())
            {
                ss  << ", ";
            }
            ss << "\"" << key << "\" : " << _LSHubTrustLevelsToString(value);
        }
    }
    ss << "}";

    return ss.str();
}

std::string
LSHubPermissionProvidedTrustLevelsToString(const LSHubPermission* perm)
{
    LOG_LS_DEBUG("%s\n", __func__);

    const TrustMap& cm = perm->trust_level_provided;

    std::stringstream ss;

    ss << "{";
    if (!cm.empty())
    {
        for (auto it = cm.begin(); it != cm.end(); ++it)
        {
            const std::string &key = it->first;
            const auto &value = it->second;

            if (it != cm.begin())
            {
                ss  << ", ";
            }
            ss << "\"" << key << "\" : " << _LSHubTrustLevelsToString(value);
        }
    }
    ss << "}";

    return ss.str();
}

std::string
LSHubPermissionProvidesToString(const LSHubPermission* perm)
{
    LOG_LS_DEBUG("%s\n", __func__);

    const CategoryMap& cm = perm->provides;

    std::stringstream ss;

    ss << "{";
    if (!cm.empty())
    {
        for (auto it = cm.begin(); it != cm.end(); ++it)
        {
            const std::string &key = it->first;
            const auto &value = it->second;

            if (it != cm.begin())
            {
                ss  << ", ";
            }
            ss << "\"" << key << "\" : " << _LSHubGroupsToString(value);
        }
    }
    ss << "}";

    return ss.str();
}

/// @brief create new instance of permissions with reference count 0
/// @param[in] service_name  service identifier
/// @param[in] exe_path      full executable path for authentication
/// @return new instance of permissions
LSHubPermission*
LSHubPermissionNew(raw_buffer service_name, const char *exe_path)
{
    LS_ASSERT(service_name.m_str != NULL);

    LOG_LS_DEBUG("%s\n", __func__);

    LSHubPermission *perm = new LSHubPermission();

    perm->service_name = g_strndup(service_name.m_str, service_name.m_len);
    perm->exe_path = g_strdup(exe_path);
    perm->inbound = _LSHubPatternQueueNewRef();
    perm->outbound = _LSHubPatternQueueNewRef();
    perm->perm_flags = NO_BUS_ROLE;

    return perm;
}

/// @brief create new instance of permissions with reference count 0
/// @param[in] service_name  service identifier
/// @param[in] exe_path      full executable path for authentication
/// @return new instance of permissions
LSHubPermission*
LSHubPermissionNew(const std::string &service_name, const char *exe_path)
{
    return LSHubPermissionNew(raw_buffer{service_name.data(), service_name.size()}, exe_path);
}

/// @brief create new instance of permissions with reference count 1
/// @param[in] service_name  service identifier
/// @param[in] exe_path      full executable path for authentication
/// @return new instance of permissions
LSHubPermission*
LSHubPermissionNewRef(raw_buffer service_name, const char *exe_path)
{
    LOG_LS_DEBUG("%s\n", __func__);

    LSHubPermission *perm = LSHubPermissionNew(service_name, exe_path);

    if (perm)
    {
        perm->ref = 1;
    }

    return perm;
}

/// @brief create new instance of permissions with reference count 1
/// @param[in] service_name  service identifier
/// @param[in] exe_path      full executable path for authentication
/// @return new instance of permissions
LSHubPermission*
LSHubPermissionNewRef(const std::string &service_name, const char *exe_path)
{
    return LSHubPermissionNewRef(raw_buffer{service_name.data(), service_name.size()}, exe_path);
}

void
LSHubPermissionRef(LSHubPermission *perm)
{
    LS_ASSERT(perm != NULL);
    LS_ASSERT(g_atomic_int_get(&perm->ref) > 0);

    LOG_LS_DEBUG("%s: ref permission\n", __func__);

    g_atomic_int_inc(&perm->ref);
}


bool
LSHubPermissionUnref(LSHubPermission *perm)
{
    LS_ASSERT(perm != NULL);
    LS_ASSERT(g_atomic_int_get(&perm->ref) > 0);

    LOG_LS_DEBUG("%s: unref permission\n", __func__);

    if (g_atomic_int_dec_and_test(&perm->ref))
    {
        LSHubPermissionFree(perm);
        return true;
    }
    return false;
}

void
LSHubPermissionFree(LSHubPermission *perm)
{
    LS_ASSERT(perm != NULL);

    LOG_LS_DEBUG("%s: free permission\n", __func__);

    g_free((char*)perm->service_name);
    g_free((char*)perm->exe_path);

    _LSHubPatternQueueUnref(perm->inbound);
    _LSHubPatternQueueUnref(perm->outbound);

    delete perm;
}

std::string LSHubPermissionDump(const LSHubPermission *perm)
{
    std::string dump;
    dump = dump + "{";
    dump = dump + "\"service\": " + "\"" + perm->service_name + "\"";
    dump = dump + ", \"executable\": " + "\"" + (perm->exe_path ? perm->exe_path : "") + "\"";
    dump = dump + ", \"inbound\": " + _LSHubPatternQueueDump(perm->inbound);
    dump = dump + ", \"outbound\": " + _LSHubPatternQueueDump(perm->outbound);
    dump = dump + ", \"requires\": " + LSHubPermissionRequiresToString(perm);
    dump = dump + ", \"provides\": " + LSHubPermissionProvidesToString(perm);
    dump = dump + ",\"providedtrustLevels\":" + LSHubPermissionProvidedTrustLevelsToString(perm);
    dump = dump + ",\"requiredtrustLevels\":" + LSHubPermissionRequiredTrustLevelsToString(perm);
    //dump = dump + ", \"access\": " + perm->
    dump = dump + "}";
    return dump;
}

void
LSHubPermissionAddAllowedInbound(LSHubPermission *perm, const char *name)
{
    LS_ASSERT(perm != NULL);
    LS_ASSERT(name != NULL);

    LOG_LS_DEBUG("%s: add name: \"%s\" as allowed inbound\n", __func__, name);

    auto pattern = mk_ptr(_LSHubPatternSpecNewRef(name), _LSHubPatternSpecUnref);
    _LSHubPatternQueueInsertSorted(perm->inbound, pattern.get()); /* increments ref count */
}

void
LSHubPermissionAddAllowedOutbound(LSHubPermission *perm, const char *name)
{
    LS_ASSERT(perm != NULL);
    LS_ASSERT(name != NULL);

    LOG_LS_DEBUG("%s: add name: \"%s\" as allowed outbound\n", __func__, name);

    auto pattern = mk_ptr(_LSHubPatternSpecNewRef(name), _LSHubPatternSpecUnref);
    _LSHubPatternQueueInsertSorted(perm->outbound, pattern.get()); /* increments ref count */
}

/// @brief Add a group to the set of required groups
///
/// @param[in,out] perm        permissions to manipulate
/// @param[in]     group_name  group name to add
/// @return false if the group is already in the set of required groups
bool
LSHubPermissionAddRequired(LSHubPermission *perm, const char *group_name)
{
    LS_ASSERT(perm != nullptr);

    LOG_LS_DEBUG("%s: add required group: \"%s\"", __func__, group_name);

    perm->requires.push_back(g_intern_string(group_name));
    return true;
}

/// @brief Add a group to the set of provided groups of a given category
///
/// @param[in,out] perm           permissions to inflate
/// @param[in]     category_name  category pattern to extend
/// @param[in]     group_name     another provided group
/// @return false if the group is already known
bool
LSHubPermissionAddProvided(LSHubPermission *perm, const char *category_name, const char *group_name)
{
    LS_ASSERT(perm != nullptr);
    LOG_LS_DEBUG("%s: add provided group: \"%s\" to category \"%s\"", __func__, group_name, category_name);
    perm->provides[category_name].push_back(g_intern_string(group_name));
    return true;
}

/// @brief Add a trust level to the set of provided groups of a given category
///
/// @param[in,out] perm           permissions to inflate
/// @param[in]     category_name  category pattern to extend
/// @param[in]     group_name     another provided group
/// @return false if the group is already known
bool
LSHubPermissionAddProvidedTrust(LSHubPermission *perm, const char *group_name, const char *trust_level)
{
    LS_ASSERT(perm != nullptr);
    LOG_LS_DEBUG("%s: add trust level: \"%s\" to provided group \"%s\"", __func__, trust_level, group_name);
    perm->trust_level_provided[group_name].push_back(g_intern_string(trust_level));
    LOG_LS_DEBUG("Trust Level: %s\n", trust_level);
    return true;
}

bool
LSHubPermissionAddRequiredTrust(LSHubPermission *perm, const char *group_name, const char *trust_level)
{
    LS_ASSERT(perm != nullptr);

    LOG_LS_DEBUG("%s: add trust level: \"%s\" to provided group \"%s\"", __func__, trust_level, group_name);
    perm->trust_level_required[group_name].push_back(g_intern_string(trust_level));
    LOG_LS_DEBUG("Trust Level: %s\n", trust_level);
    return true;
}

bool
LSHubPermissionIsEqual(const LSHubPermission *a, const LSHubPermission *b)
{
    LS_ASSERT(a != NULL);
    LS_ASSERT(b != NULL);

    if (a == b)
        return true;

    return !strcmp(a->service_name, b->service_name) &&
           !g_strcmp0(a->exe_path, b->exe_path) &&
           _LSHubPatternQueueIsEqual(a->inbound, b->inbound) &&
           _LSHubPatternQueueIsEqual(a->outbound, b->outbound);
}

/// @brief Merge inbound and outbound permissions
/// @param[in,out] to
/// @param[in] from
void
LSHubPermissionMergePermissions(LSHubPermission *to, const LSHubPermission *from)
{
    _LSHubPatternQueueMergeInto(to->inbound, from->inbound);
    _LSHubPatternQueueMergeInto(to->outbound, from->outbound);
}

/// @brief Merge inbound and outbound permissions, allow dups
/// @param[in,out] to
/// @param[in] from
void
LSHubPermissionMergePermissionsAllowDups(LSHubPermission *to, const LSHubPermission *from)
{
    _LSHubPatternQueueMergeIntoAllowDups(to->inbound, from->inbound);
    _LSHubPatternQueueMergeIntoAllowDups(to->outbound, from->outbound);
}

void
LSHubPermissionRemovePermissions(LSHubPermission *from, const LSHubPermission *what)
{
    _LSHubPatternQueueExtractFrom(from->inbound, what->inbound);
    _LSHubPatternQueueExtractFrom(from->outbound, what->outbound);
}

/// @} END OF GROUP LunaServiceHubSecurity
/// @endcond


// ***************************************************************************************************
/* bool
LSHubPermissionAddAccess(LSHubPermission *perm, bool access)
{
    LS_ASSERT(perm != nullptr);

    std::string group_name = getGroupAccess();

    LOG_LS_DEBUG("%s: add provided access: \"%s\" to category \"%d\"", __func__, group_name, access);
    perm->groupAccess[group_name] = gboolean(access);

    return true;
} */
// ***************************************************************************************************
