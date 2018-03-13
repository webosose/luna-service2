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

#include "signal_map.hpp"

#include "transport.h"
#include "transport_client.h"

#include "client_map.hpp"

/// @cond INTERNAL
/// @addtogroup LunaServiceHub
/// @{

_SignalMap *signal_map = NULL;

_SignalMap*
_SignalMapNew(void)
{
    _SignalMap *ret = g_new0(_SignalMap, 1);

    ret->category_map = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, (GDestroyNotify)_LSTransportClientMapFree);
    ret->method_map = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, (GDestroyNotify)_LSTransportClientMapFree);

    return ret;
}

void
_SignalMapFree(_SignalMap *signal_map)
{
    g_hash_table_unref(signal_map->category_map);
    g_hash_table_unref(signal_map->method_map);

#ifdef MEMCHECK
    memset(signal_map, 0xFF, sizeof(_SignalMap));
#endif

    g_free(signal_map);
}

/// @} END OF GROUP LunaServiceHub
/// @endcond
