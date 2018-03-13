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

#ifndef _CLIENT_MAP_HPP_
#define _CLIENT_MAP_HPP_

#include <glib.h>

/// @cond INTERNAL
/// @addtogroup LunaServiceHub
/// @{

struct LSTransportClient;
struct LSTransportMessage;

typedef struct LSTransportClient _LSTransportClient;
typedef struct LSTransportMessage _LSTransportMessage;

/// @brief Map of transport clients
typedef struct _LSTransportClientMap {
    GHashTable *map;
} _LSTransportClientMap;

_LSTransportClientMap*
_LSTransportClientMapNew(void);

void
_LSTransportClientMapFree(_LSTransportClientMap *map);

void
_LSTransportClientMapAddRefClient(_LSTransportClientMap *map, _LSTransportClient *client);

bool
_LSTransportClientMapUnrefClient(_LSTransportClientMap *map, _LSTransportClient *client);

bool
_LSTransportClientMapRemove(_LSTransportClientMap *map, _LSTransportClient *client);

bool
_LSTransportClientMapIsEmpty(_LSTransportClientMap *map);

void
_LSTransportClientMapForEach(_LSTransportClientMap *map, GHFunc func, _LSTransportMessage *message);

/// @} END OF GROUP LunaServiceHub
/// @endcond

#endif //_CLIENT_MAP_HPP_
