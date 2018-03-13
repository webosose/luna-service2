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

#ifndef _ACTIVE_ROLE_MAP_HPP_
#define _ACTIVE_ROLE_MAP_HPP_

#include <unistd.h>

#include "util.hpp"

struct LSError;
struct LSHubRole;
struct LSTransportClient;

typedef struct LSError LSError;
typedef struct LSHubRole LSHubRole;
typedef struct LSTransportClient _LSTransportClient;

GHashTablePointer LSHubActiveRoleMapCreate(void);

bool
LSHubActiveRoleMapAddRef(pid_t pid, LSHubRole *role, LSError *lserror);

bool
LSHubActiveRoleMapUnref(pid_t pid);

LSHubRole*
LSHubActiveRoleMapLookup(pid_t pid);

/* call this when a client disconnects so that the active role map can be kept
 * accurate */

bool
LSHubActiveRoleMapClientRemove(const _LSTransportClient *client, LSError *lserror);

#endif //_ACTIVE_ROLE_MAP_HPP_
