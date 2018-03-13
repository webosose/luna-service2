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

#ifndef _ACTIVE_PERMISSION_MAP_H_
#define _ACTIVE_PERMISSION_MAP_H_

struct LSError;
struct LSHubPermission;
struct LSTransportClient;

typedef struct LSError LSError;
typedef struct LSHubPermission LSHubPermission;
typedef struct LSTransportClient _LSTransportClient;

LSHubPermission*
LSHubActivePermissionMapLookup(const char *active_service_id);

LSHubPermission*
LSHubActivePermissionMapLookup(const _LSTransportClient *client);

bool
LSHubActivePermissionMapAddRef(LSHubPermission *perm, const char *active_service_id);

bool
LSHubActivePermissionMapUnref(const char *active_service_id);

bool
LSHubActivePermissionMapClientAdd(const _LSTransportClient *client, const char *service_name,
                                  const char *active_service_id, LSError *lserror);

/* call this when a client disconnects to remove active permissions for disconnected client
 * from the map */
bool
LSHubActivePermissionMapClientRemove(const _LSTransportClient *client, LSError *lserror);

#endif //_ACTIVE_PERMISSION_MAP_H_
