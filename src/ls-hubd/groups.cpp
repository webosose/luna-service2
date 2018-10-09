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

#include "groups.hpp"

#include "error.h"
#include "pattern.hpp"
#include "simple_pbnjson.h"

/// @cond INTERNAL
/// @addtogroup LunaServiceHubSecurity
/// @{

/// @brief Create new role for given executable
///
/// @param[in] id Full path to the executable or appID
/// @param[in] type
/// @param[in] role_flags
/// @return New instance of role
LSHubGroups*
LSHubGroupsNew(bool access)
{
    LSHubGroups *sec_group = new LSHubGroups();

    sec_group->access = access;

    return sec_group;
}

void
LSHubGroupsFree(LSHubGroups *sec_group)
{
    LS_ASSERT(sec_group != NULL);
    LOG_LS_DEBUG("%s\n", __func__);

    delete sec_group;
}

/// @} END OF GROUP LunaServiceHubSecurity
/// @endcond
