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

#ifndef _CLIENT_ID_HPP_
#define _CLIENT_ID_HPP_

#include <glib.h>

/// @cond INTERNAL
/// @addtogroup LunaServiceHub
/// @{

struct LSTransportClient;
typedef struct LSTransportClient _LSTransportClient;

typedef struct _LocalName {
    char *name;
} _LocalName;

typedef struct _ClientId {
    int ref;                    /**< ref count */
    char *service_name;         /**< service name (or NULL if it doesn't have one */
    _LSTransportClient *client; /**< underlying transport client, so we can
                                     initiate messages */
    _LocalName local;           /**< local name */
    bool is_monitor;            /**< true if this client is the monitor */
    GHashTable *categories;     /**< map of registered categories to method names lists */
} _ClientId;

extern _ClientId *monitor;        /**< non-NULL when a monitor is connected */

_ClientId*
_LSHubClientIdLocalNew(const char *service_name, const char *unique_name, _LSTransportClient *client);

void
_LSHubClientIdLocalFree(_ClientId *id);

_ClientId*
_LSHubClientIdLocalNewRef(const char *service_name, const char *unique_name, _LSTransportClient *client);

void
_LSHubClientIdLocalRef(_ClientId *id);

void
_LSHubClientIdLocalUnref(_ClientId *id);

void
_LSHubClientIdLocalUnrefVoid(void *id);

/// @} END OF GROUP LunaServiceHub
/// @endcond

#endif //_CLIENT_ID_
