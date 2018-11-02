// Copyright (c) 2018-2019 LG Electronics, Inc.
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

#ifndef _GROUPS_DESCRIPTION_HPP_
#define _GROUPS_DESCRIPTION_HPP_

#include <glib.h>
#include <memory>

#include "error.h"
#include "conf.hpp"
#include "permission.hpp"

typedef GSList _LSHubTrustLevels;

// @cond INTERNAL

// struct representing groups
struct LSHubGroups {
    int ref;                    // ref count
    char **groups_name;         // names of groups provided
    int num_groups;             // number of groups
    bool access;                // public true or false
    TrustMap trustLevel;
    //_LSHubTrustLevels trustLevel;    // trust level
};

//typedef std::unordered_map<std::string, NGroups> TrustMap;

typedef std::unique_ptr<LSHubGroups, bool(*)(LSHubGroups*)> GroupsPtr;

LSHubGroups*
LSHubGroupsNew(bool access);

static inline LSHubGroups*
LSHubGroupsNewRef(bool access)
{
    LSHubGroups *sec_group = LSHubGroupsNew(access);

    sec_group->ref = 1;

    return sec_group;
}

static inline void
LSHubGroupsRef(LSHubGroups *sec_group)
{
    LS_ASSERT(sec_group != NULL);
    LS_ASSERT(g_atomic_int_get(&sec_group->ref) > 0);

    LOG_LS_DEBUG("%s\n", __func__);

    g_atomic_int_inc(&sec_group->ref);
}

void
LSHubGroupsFree(LSHubGroups *sec_group);

/* returns true if the ref count went to 0 and the role was freed */
static inline bool
LSHubGroupsUnref(LSHubGroups *sec_group)
{
    LS_ASSERT(sec_group != NULL);
    LS_ASSERT(g_atomic_int_get(&sec_group->ref) > 0);

    LOG_LS_DEBUG("%s\n", __func__);

    if (g_atomic_int_dec_and_test(&sec_group->ref))
    {
        LSHubGroupsFree(sec_group);
        return true;
    }

    return false;
}

// @endcond INTERNAL

#endif // _GROUPS_DESCRIPTION_HPP_
