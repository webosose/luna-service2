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

#ifndef _SIGNAL_MAP_HPP_
#define _SIGNAL_MAP_HPP_

#include <glib.h>

/// @cond INTERNAL
/// @addtogroup LunaServiceHub
/// @{

typedef struct _SignalMap {
    GHashTable *category_map;   /**< category to _LSTransportClient list */
    GHashTable *method_map;     /**< category/method to _LSTransportClient list */

    /*
     * TODO: fast way to go from _LSTransportClient to any categories and
     * methods to that it has registered
     *
     * this reverse lookup is so that we can quickly remove all items in the
     * above hash table for a client that goes down
     */
    GHashTable *client_map;     /**< _LSTransportClient* to items (elements) in
                                     the above hashed lists */
} _SignalMap;

extern _SignalMap *signal_map;    /**< keeps track of signals */

/**
 *******************************************************************************
 * @brief Allocate a new signal map, which has a hash of category strings to
 * @ref _LSTransportClientMap and hash of method strings to @ref
 * _LSTransportClientMap.
 *
 * @retval map on success
 * @retval NULL on failure
 *******************************************************************************
 */
_SignalMap*
_SignalMapNew();

/**
 *******************************************************************************
 * @brief Free a signal map.
 *
 * @param  signal_map   IN  map to free
 *******************************************************************************
 */
void
_SignalMapFree(_SignalMap *signal_map);

/// @} END OF GROUP LunaServiceHub
/// @endcond

#endif //_SIGNAL_MAP_HPP_
