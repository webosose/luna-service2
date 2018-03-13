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

#include "groups_map.hpp"

#include <algorithm>
#include <sstream>

#include "error.h"

/// @cond INTERNAL
/// @addtogroup LunaServiceHubSecurity
/// @{

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
}

GroupsMap::GroupsMap()
    : _groups(Trie<Data>::PtrT(new Trie<Data>))
{
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
    };

    _groups->Remove(service_name, action);
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
        auto dump_required = [&oss](const std::string &prefix, const char *wildcard, const Groups &groups)
        {
            for (const char *group : groups)
            {
                oss << "Required," << prefix << wildcard;
                oss << ',' << group;
                oss << '\n';
            }
        };

        if (!data.required_pattern.empty())
            dump_required(prefix, "*", data.required_pattern);

        if (!data.required_terminal.empty())
            dump_required(prefix, "", data.required_terminal);
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
        auto dump_provided = [&oss](const std::string &prefix, const char *wildcard, const CategoryMap &categories)
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
            dump_provided(prefix, "*", data.provided_pattern);

        if (!data.provided_terminal.empty())
            dump_provided(prefix, "", data.provided_terminal);
    };

    _groups->Visit(action);

    return oss.str();
}

/// @} END OF GROUP LunaServiceHubSecurity
/// @endcond
