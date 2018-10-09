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

#ifndef _GROUPS_MAP_HPP_
#define _GROUPS_MAP_HPP_

#include <memory>

#include "permission.hpp"
#include "trie.hpp"

/// @cond INTERNAL
/// @addtogroup LunaServiceHubSecurity
/// @{

#ifdef SECURITY_COMPATIBILITY

#define PUBLIC_SECGROUP_NAME    "public"
#define PRIVATE_SECGROUP_NAME   "private"

#endif //SECURITY_COMPATIBILITY

class GroupsMap
{
public:
    GroupsMap();

    void AddProvided(const char *service_name, const char *category_name, const char *group_name);
    void RemoveProvided(const char *service_name, const char *category_name, const char *group_name);

    CategoryMap GetProvided(const char *service_name) const;

    void AddRequired(const char *service_name, const char *group_name);
    void RemoveRequired(const char *service_name, const char *group_name);

    Groups GetRequired(const char *service_name) const;

    std::string DumpRequiredCsv() const;
    std::string DumpProvidedCsv() const;
	std::string DumpTrustLevelCsv() const;

private:
    struct Data
    {
        Groups required_pattern;
        Groups required_terminal;
        CategoryMap provided_pattern;
        CategoryMap provided_terminal;
		TrustMap trust_level;

        Data() = default;
        Data(const Data &) = delete;
        Data& operator=(const Data &) = delete;

        bool IsEmpty() const;
    };

    Trie<Data>::PtrT _groups;
};

/// @} END OF GROUP LunaServiceHubSecurity
/// @endcond

#endif //_GROUPS_MAP_HPP_
