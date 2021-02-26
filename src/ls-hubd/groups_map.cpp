// Copyright (c) 2014-2021 LG Electronics, Inc.
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

#include "groups_map.hpp"

#include <algorithm>
#include <sstream>

#include "error.h"

/// @cond INTERNAL
/// @addtogroup LunaServiceHubSecurity
/// @{

static std::string
GroupsToString(const Groups& s)
{
    std::stringstream ss;

    ss << "[";
    if (!s.empty())
    {
        auto it = s.begin();
        ss << "\"" << *it << "\"";

        for (++it; it != s.end(); ++it)
            ss << ", \"" << *it << "\"";
    }
    ss << "]";

    return  ss.str();
}

static inline bool is_pattern(const char *str)
{
    return str[strlen(str) - 1] == '*';
}

bool GroupsMap::Data::IsEmpty() const
{
    return required_pattern.empty() &&
           required_terminal.empty() &&
           provided_pattern.empty() &&
           provided_terminal.empty();
           // Enable below when everyone follows trust level + group
           // trust_level_provided.empty() &&
           // trust_level_required.empty() &&
           // provided_terminal.empty();
}

GroupsMap::GroupsMap()
    : _groups(Trie<Data>::PtrT(new Trie<Data>))
{
}

void GroupsMap::AddProvidedTrustLevel(const char *service_name, const TrustMap &map) {

// TBD: Get service name as paramete
// from that get categories and groups
//    LS_ASSERT(trust != nullptr);
    LS_ASSERT(service_name != nullptr);
    auto *node = _groups->Get(service_name);
    if (!node)
    {
        LOG_LS_DEBUG("ERRR %s : service_name [ %s ] not found in trie tree",__func__, service_name);
    }
    else
    {
        LOG_LS_DEBUG("%s : FOUND : service_name [ %s ]",__func__, service_name);
        for (auto &item : map)
        {
          const std::string group = item.first;
          for (auto &trust : item.second)
          {
            node->trust_level_provided[group].push_back(g_intern_string(trust));
          }
        }
        std::string provided = DumpProvidedTrustLevelForServiceCsv(service_name);
        LOG_LS_DEBUG("%s : FOUND : service_name [ %s ], provided map [%s]",__func__, service_name, provided.c_str());
    }
}

void GroupsMap::RemoveProvidedTrustLevel(const char *service_name,
                                                     const char *group,
                                                     const char *trust)
{
    // TBD: Remove provided trust level
    // If we keep these functions seperate, then we have to make sure that these are called
    // before removing required and provided groups, because
    LS_ASSERT(service_name != nullptr);
    LS_ASSERT(group != nullptr);
    LS_ASSERT(trust != nullptr);
    auto *node = _groups->Get(service_name);
    if (!node)
    {
        LOG_LS_DEBUG("ERRR %s : service_name [ %s ] not found in trie tree",__func__, service_name);
    }
    else
    {
        LOG_LS_DEBUG("%s : FOUND : service_name [ %s ]",__func__, service_name);
        auto action = [service_name, group, trust](const char *key, Data &data)
        {
            auto &container = data.trust_level_provided;
            container[group].erase(trust);
            if (container[group].empty())
                container.erase(group);
        };
        _groups->Remove(service_name, action);
    }
}

void GroupsMap::AddRequiredTrustLevel(const char *service_name, const TrustMap &map)
{
    // TBD: Get service name as paramete
    // from that get categories and groups
    //    LS_ASSERT(trust != nullptr);
    LS_ASSERT(service_name != nullptr);
    //TBD: Add [trust : groups] map entry provided by app/services
    auto *node = _groups->Get(service_name);
    if (!node) {
        LOG_LS_DEBUG("ERRR %s : service_name [ %s ] not found in trie tree",__func__, service_name);
    } else {
        LOG_LS_DEBUG("%s : FOUND : service_name [ %s ]",__func__, service_name);
        for (auto &item : map)
        {
            const std::string group = item.first;
            for (auto &trust : item.second)
            {
                node->trust_level_required[group].push_back(g_intern_string(trust));
            }
        }
        std::string required = DumpRequiredTrustLevelForServiceCsv(service_name);
    }
}

void GroupsMap::AddRequiredTrustLevelAsString(const char *service_name, const std::string &trustLevel)
{
// TBD: Get service name as paramete
// from that get categories and groups
//    LS_ASSERT(trust != nullptr);
    LS_ASSERT(service_name != nullptr);
    //TBD: Add [trust : groups] map entry provided by app/services
    auto *node = _groups->Get(service_name);
    if (!node) {
        LOG_LS_DEBUG("ERRR %s : service_name [ %s ] not found in trie tree",__func__, service_name);
    } else {
        LOG_LS_DEBUG("%s : FOUND : service_name [ %s ]",__func__, service_name);
        node->trustLevel = trustLevel;
        LOG_LS_DEBUG("%s : FOUND : service_name [ %s ], required trustLevel [%s]",__func__, service_name, trustLevel.c_str());
    }
}

void GroupsMap::RemoveRequiredTrustLevel(const char *service_name,
                                                     const char *group,
                                                     const char *trust)
{
    LS_ASSERT(service_name != nullptr);
    LS_ASSERT(group != nullptr);
    LS_ASSERT(trust != nullptr);
    auto *node = _groups->Get(service_name);
    if (!node)
    {
        LOG_LS_DEBUG("ERRR %s : service_name [ %s ] not found in trie tree",__func__, service_name);
    }
    else
    {
        LOG_LS_DEBUG("%s : FOUND : service_name [ %s ]",__func__, service_name);
        auto action = [service_name, group, trust](const char *key, Data &data)
        {
            auto &container = data.trust_level_required;
            container[group].erase(trust);
            if (container[group].empty())
                container.erase(group);
        };
        _groups->Remove(service_name, action);
    }
}

/// @brief Add provided ACG to the security data
///
/// @param[in] service_name
/// @param[in] category_name Category/method pattern
/// @param[in] group_name ACG name to be added to the corresponding set
void GroupsMap::AddProvided(const char *service_name, const char *category_name, const char *group_name)
{
    LS_ASSERT(service_name != nullptr);
    LS_ASSERT(category_name != nullptr);
    LS_ASSERT(group_name != nullptr);

    auto *node = _groups->Add(service_name);

    // Leave only category pattern for method matching
    const char *category_only = strchr(category_name, '/');
    const char *category_pattern = category_only ? category_only : "/";
    auto& container = is_pattern(service_name) ? node->provided_pattern : node->provided_terminal;
    container[category_pattern].push_back(g_intern_string(group_name));
}

/// @brief Remove provided ACG from the security data
///
/// @param[in] service_name
/// @param[in] category_name Category/method pattern
/// @param[in] group_name ACG name to be removed from the corresponding set
void GroupsMap::RemoveProvided(const char *service_name, const char *category_name, const char *group_name)
{
    LS_ASSERT(service_name != nullptr);
    LS_ASSERT(category_name != nullptr);
    LS_ASSERT(group_name != nullptr);

    // Leave only category pattern for method matching
    const char *category_only = strchr(category_name, '/');
    const char *category_pattern = category_only ? category_only : "/";
    const char *group = g_intern_string(group_name);

    auto action = [category_pattern, group](const char *key, Data &data)
    {
        auto &container = !(*key) ? data.provided_terminal : data.provided_pattern;
        container[category_pattern].erase(group);
        if (container[category_pattern].empty()) container.erase(category_pattern);
        //TBD: Here Do we have to remove required trust levels, or keep removal seperate? Food fot thought
    };

    _groups->Remove(service_name, action);
}

/// @brief Add group name to the set of required
///
/// @param[in] service_name  Target service name
/// @param[in] group_name    ACG name
void GroupsMap::AddRequired(const char *service_name, const char *group_name)
{
    LS_ASSERT(service_name != nullptr);
    LS_ASSERT(group_name != nullptr);

    auto node = _groups->Add(service_name);

    auto &container = is_pattern(service_name) ? node->required_pattern : node->required_terminal;
    container.push_back(g_intern_string(group_name));
}

/// @brief Remove group name from the set of required
///
/// @param[in] service_name  Target service name
/// @param[in] group_name    ACG name
void GroupsMap::RemoveRequired(const char *service_name, const char *group_name)
{
    LS_ASSERT(service_name != nullptr);
    LS_ASSERT(group_name != nullptr);

    const char *group = g_intern_string(group_name);

    auto action = [group](const char *key, Data &data)
    {
        auto &container = !(*key) ? data.required_terminal : data.required_pattern;
        container.erase(group);
        //TBD: Here Do we have to remove required trust levels, or keep removal seperate? Food fot thought
    };

    _groups->Remove(service_name, action);
}

/// @brief Get set of required trusts for a service
///
/// @param[in] service_name
/// @return Set of required trustlevel
TrustMap GroupsMap::GetProvidedTrust(const char *service_name) const
{
    TrustMap trust_map;

    auto action = [&trust_map](const Data &data)
    {
        for (const auto &c : data.trust_level_provided)
            trust_map[c.first].insert(c.second);
    };

    auto leaf = _groups->Search(service_name, action);
//    if (leaf)
//    {
//        for (const auto &c : leaf->trust_level)
//            trust_map[c.first].insert(c.second);
//    }

    return trust_map;
}

TrustMap GroupsMap::GetRequiredTrust(const char *service_name) const
{
    TrustMap trust_map;

    auto action = [&trust_map](const Data &data)
    {
        for (const auto &c : data.trust_level_required)
            trust_map[c.first].insert(c.second);
    };

    auto leaf = _groups->Search(service_name, action);
//    if (leaf)
//    {
//        for (const auto &c : leaf->trust_level)
//            trust_map[c.first].insert(c.second);
//    }

    return trust_map;
}

std::string GroupsMap::GetRequiredTrustAsString(const char *service_name) const
{
    std::string trust_string;
    auto action = [&trust_string](const Data &data)
    {
         //if (data.trust_level_required.empty())
         //{
         //    trust_string = DEFAULT_TRUST_LEVEL;
         //}
         //else
         {
             //trust_string = (data.trust_level_required.begin()->second)[0];// It all will be same, so first string is enough
             trust_string = data.trustLevel;
         }
    };

    auto leaf = _groups->Search(service_name, action);
    // If trust is not available, default is "dev"
    if (trust_string.empty())
        trust_string = DEFAULT_TRUST_LEVEL;
    LOG_LS_DEBUG("%s : trust_string[ %s ]\n", __func__, trust_string.c_str());
    return trust_string;
}

/// @brief Get set of required groups for a service
///
/// @param[in] service_name
/// @return Set of required groups
Groups GroupsMap::GetRequired(const char *service_name) const
{
    Groups groups;

    auto action = [&groups](const Data &data)
    {
        groups.insert(data.required_pattern);
    };

    auto leaf = _groups->Search(service_name, action);
    if (leaf)
        groups.insert(leaf->required_terminal);

    return groups;
}

/// @brief Get provided ACG info (map category pattern to set of groups)
///
/// @param[in] service_name
/// @return Category pattern map to set of groups
CategoryMap GroupsMap::GetProvided(const char *service_name) const
{
    CategoryMap category_map;

    auto action = [&category_map](const Data &data)
    {
        for (const auto &c : data.provided_pattern)
            category_map[c.first].insert(c.second);
    };

    auto leaf = _groups->Search(service_name, action);
    if (leaf)
    {
        for (const auto &c : leaf->provided_terminal)
            category_map[c.first].insert(c.second);
    }

    return category_map;
}

/// @brief Dump client permissions into a CSV text
///
/// @return Text representation of client permissions
std::string GroupsMap::DumpRequiredCsv() const
{
    std::ostringstream oss;

    auto action = [&oss](const std::string &prefix, const Data &data)
    {
        auto dump_required = [&oss, &prefix](const char *wildcard, const Groups &groups)
        {
            for (const char *group : groups)
            {
                oss << "Required," << prefix << wildcard;
                oss << ',' << group;
                oss << '\n';
            }
        };

        if (!data.required_pattern.empty())
            dump_required("*", data.required_pattern);

        if (!data.required_terminal.empty())
            dump_required("", data.required_terminal);
    };

    _groups->Visit(action);

    return oss.str();
}

/// @brief Dump API permissions into a CSV text
///
/// @return Text representation of API permissions
std::string GroupsMap::DumpProvidedCsv() const
{
    std::ostringstream oss;

    auto action = [&oss](const std::string &prefix, const Data &data)
    {
        auto dump_provided = [&oss, &prefix](const char *wildcard, const CategoryMap &categories)
        {
            for (auto &entry : categories)
            {
                for (const char *group : entry.second)
                {
                    // Tag
                    oss << "Provided," << prefix << wildcard;
                    // Category
                    oss << ',' << entry.first;
                    // Sorted list of groups
                    oss << ',' << group;
                    oss << '\n';
                }
            }
        };

        if (!data.provided_pattern.empty())
            dump_provided("*", data.provided_pattern);

        if (!data.provided_terminal.empty())
            dump_provided("", data.provided_terminal);
    };

    _groups->Visit(action);

    return oss.str();
}

std::string  GroupsMap::DumpRequiredTrustLevelCsv() const
{
    std::ostringstream oss;
    // parameter prefix is needed for Visit(action) template function
    auto action = [&oss](const std::string &prefix, const Data &data)
    {
        (void)prefix;
        auto dump_trust = [&oss](const TrustMap &trustLevels)
        {
            for(auto &entry : trustLevels)
            {
                for(const char *group : entry.second)
                {
                    // Tag
                    oss << "Required Group," << entry.first;
                    // Sorted list of trust levels
                    oss << ',' << group;
                    oss << '\n';
                }
            }
        };

        if(data.trust_level_required.empty())
        {
             LOG_LS_DEBUG("%s : ERR!No Trust level info in tree !!!! ", __func__);
        }
        else
        {
            dump_trust(data.trust_level_required);
        }
    };
    _groups->Visit(action);

    return oss.str();
}

std::string  GroupsMap::DumpProvidedTrustLevelCsv() const
{
    std::ostringstream oss;
    // parameter prefix is needed for Visit(action) template function
    auto action = [&oss](const std::string &prefix, const Data &data)
    {
        (void)prefix;
        auto dump_trust = [&oss](const TrustMap &trustLevels)
        {
            for(auto &entry : trustLevels)
            {
                for(const char *group : entry.second)
                {
                    // Tag
                    oss << "Provided Group," << entry.first;
                    // Sorted list of trust levels
                    oss << ',' << group;
                    oss << '\n';
                }
            }
        };

        if(data.trust_level_provided.empty())
        {
             LOG_LS_DEBUG("%s : ERR!No Trust level info in tree !!!! ", __func__);
        }
        else
        {
            dump_trust(data.trust_level_provided);
        }
    };
    _groups->Visit(action);

    return oss.str();
}

std::string  GroupsMap::DumpRequiredTrustLevelCsv(const char* service, const  TrustMap &required) const
{
    std::ostringstream oss;

    auto dump_trust = [&oss](const std::string& service_name, const TrustMap &trustLevels)
    {
        oss << "Service Name: " << service_name;
        oss << std::endl;
        for(auto &entry : trustLevels)
        {
            for(const char *group : entry.second)
            {
                // Tag
                oss << "Required Group," << entry.first;
                // Sorted list of trust levels
                oss << ',' << group;
                oss << std::endl;
            }
        }
    };

    if(required.empty())
    {
        oss << __func__ << " : ERR!No Trust level info in tree for [ " << service << " ] !!!! " << std::endl;
    }
    else
    {
        dump_trust(std::string(service), required);
    }

    return oss.str();
}

std::string  GroupsMap::DumpProvidedTrustLevelCsv(const char* service, const  TrustMap &provided) const
{
    std::ostringstream oss;

    auto dump_trust = [&oss](const std::string &service_name, const TrustMap &trustLevels)
    {
        oss << "Service Name: " << service_name;
        oss << std::endl;
        for(auto &entry : trustLevels)
        {
            for(const char *group : entry.second)
            {
                // Tag
                oss << "Provided Group," << entry.first;
                // Sorted list of trust levels
                oss << ',' << group;
                oss << std::endl;
            }
        }
    };

    if(provided.empty())
    {
        oss << __func__ << " : ERR!No Trust level info in tree for [ " << service << " ] !!!! " << std::endl;
    }
    else
    {
        dump_trust(std::string(service), provided);
    }

    return oss.str();
}

std::string  GroupsMap::DumpProvidedTrustLevelForServiceCsv(const char* service) const
{
    std::string map_in_string;
    TrustMap provided = GetProvidedTrust(service);
    map_in_string = DumpProvidedTrustLevelCsv(service, provided);
    return map_in_string;
}
std::string  GroupsMap::DumpRequiredTrustLevelForServiceCsv(const char* service) const
{
    std::string map_in_string;
    TrustMap required = GetRequiredTrust(service);
    map_in_string = DumpRequiredTrustLevelCsv(service, required);
    return map_in_string;
}

/// @} END OF GROUP LunaServiceHubSecurity
/// @endcond
