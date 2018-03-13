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

#include "client_map.hpp"

#include "transport.h"

/// @cond INTERNAL
/// @addtogroup LunaServiceHub
/// @{

/**
 ********************************************************************************
 * @brief Allocate a new _LSTransportClientMap, which has a key of
 * _LSTransportClient* and value of a ref count (stored in ptr).
 *
 * @retval map on success
 * @retval  NULL on failure
 ********************************************************************************/
_LSTransportClientMap*
_LSTransportClientMapNew(void)
{
    _LSTransportClientMap *ret = g_new0(_LSTransportClientMap, 1);

    ret->map = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);

    return ret;
}

/**
 ********************************************************************************
 * @brief Free a LSTransportClientMap.
 *
 * @param  map  IN  map to free
 ********************************************************************************/
void
_LSTransportClientMapFree(_LSTransportClientMap *map)
{
    g_hash_table_unref(map->map);

#ifdef MEMCHECK
    memset(map, 0xFF, sizeof(_LSTransportClientMap));
#endif

    g_free(map);
}

/**
 ********************************************************************************
 * @brief Add a client to the map with ref count of 1 if it's not in the map.
 * Otherwise, if it is already in the map, increment the ref count.
 *
 * @param  map      IN  map
 * @param  client   IN  client
 ********************************************************************************/
void
_LSTransportClientMapAddRefClient(_LSTransportClientMap *map, _LSTransportClient *client)
{
    gpointer value = g_hash_table_lookup(map->map, client);

    if (value == NULL)
    {
        _LSTransportClientRef(client);

        /* add with ref count of 1 */
        g_hash_table_replace(map->map, client, GINT_TO_POINTER(1));
    }
    else
    {
        /* increment ref count */
        gint new_value = GPOINTER_TO_INT(value) + 1;
        g_hash_table_replace(map->map, client, GINT_TO_POINTER(new_value));
    }
}

/**
 ********************************************************************************
 * @brief Decrement the client ref count in the map. Remove the client from
 * the map if the ref count goes to 0.
 *
 * @param  map      IN  map
 * @param  client   IN  client
 *
 * @retval  true if client was found in map
 * @retval  false if client was not found in map
 ********************************************************************************/
bool
_LSTransportClientMapUnrefClient(_LSTransportClientMap *map, _LSTransportClient *client)
{
    gpointer value = g_hash_table_lookup(map->map, client);

    if (value)
    {
        gint new_value = GPOINTER_TO_INT(value) - 1;

        if (new_value == 0)
        {
            g_hash_table_remove(map->map, client);
            _LSTransportClientUnref(client);
        }
        else
        {
            g_hash_table_replace(map->map, client, GINT_TO_POINTER(new_value));
        }
        return true;
    }
    return false;
}

/**
 ********************************************************************************
 * @brief Remove a client from the map irrespective of the ref count in the
 * map.
 *
 * @param  map      IN  map
 * @param  client   IN  client
 *
 * @retval  true if client was found in map
 * @retval  false if client was not found in map
 ********************************************************************************/
bool
_LSTransportClientMapRemove(_LSTransportClientMap *map, _LSTransportClient *client)
{
    gpointer value = g_hash_table_lookup(map->map, client);

    if (value)
    {
        g_hash_table_remove(map->map, client);
        _LSTransportClientUnref(client);
        return true;
    }
    return false;
}

/**
 ********************************************************************************
 * @brief Check to see if client map is empty.
 *
 * @param  map  IN  map
 *
 * @retval  true if map is empty
 * @retval  false otherwise
 ********************************************************************************/
bool
_LSTransportClientMapIsEmpty(_LSTransportClientMap *map)
{
    LS_ASSERT(map != NULL);

    if (g_hash_table_size(map->map) == 0)
    {
        return true;
    }
    return false;
}

/**
 ********************************************************************************
 * @brief Call the specified function for each item in the map.
 *
 * @param  map      IN  map
 * @param  func     IN  callback
 * @param  message  IN  message to pass as data to callback
 ********************************************************************************/
void
_LSTransportClientMapForEach(_LSTransportClientMap *map, GHFunc func, _LSTransportMessage *message)
{
    g_hash_table_foreach(map->map, func, message);
}

/// @} END OF GROUP LunaServiceHub
/// @endcond
