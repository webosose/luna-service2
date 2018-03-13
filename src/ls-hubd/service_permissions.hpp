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

#ifndef _SERVICE_PERMISSIONS_HPP_
#define _SERVICE_PERMISSIONS_HPP_

#include <glib.h>
#include <memory>

struct LSError;
struct LSHubPermission;

typedef struct LSError LSError;
typedef GSList _LSHubPermissionQueue;

/// @cond INTERNAL
/// @addtogroup LunaServiceHubSecurity
/// @{

/// @brief Collected permissions for a given service
///
/// The same service can be mentioned in different role files for different ids.
/// Thus, when looking for exact permissions, first we lookup by service name,
/// then search among permissions for different ids.
/// If we couldn't find permission by id fallback to default permissions that is
/// merge of all permissions for service
struct LSHubServicePermissions {
    int ref;                               //< Reference count
    LSHubPermission *default_permission;   //< First-found fall-back permission
    _LSHubPermissionQueue *permissions;    //< List of permissions for different executables
};

typedef std::unique_ptr<LSHubServicePermissions, void(*)(LSHubServicePermissions*)> PermissionsPtr;

LSHubServicePermissions*
LSHubServicePermissionsNew(const char *service_name);

LSHubServicePermissions*
LSHubServicePermissionsNewRef(const char *service_name);

void
LSHubServicePermissionsUnref(LSHubServicePermissions *perms);

void
LSHubServicePermissionsFree(LSHubServicePermissions *perms);

void
LSHubServicePermissionsAddPermissionRef(LSHubServicePermissions *perms, LSHubPermission *perm);

void
LSHubServicePermissionsUnrefPermission(LSHubServicePermissions *perms, const char* exe_path);

LSHubPermission*
LSHubServicePermissionsLookupPermission(const LSHubServicePermissions *perms, const char *exe_path);

/// @} END OF GROUP LunaServiceHubSecurity
/// @endcond

#endif //_SERVICE_PERMISSIONS_HPP_
