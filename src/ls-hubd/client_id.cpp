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

#include "client_id.hpp"

#include "transport.h"

/// @cond INTERNAL
/// @addtogroup LunaServiceHub
/// @{

_ClientId *monitor = NULL;

/**
 ********************************************************************************
 * @brief Allocate memory for a new client id.
 *
 * @param  service_name     IN  name of service provided by client (or NULL)
 * @param  unique_name      IN  unique name of client
 * @param  client           IN  underlying transport client
 *
 * @retval  client on success
 * @retval  NULL on failure
 ********************************************************************************/
_ClientId*
_LSHubClientIdLocalNew(const char *service_name, const char *unique_name, _LSTransportClient *client)
{
    _ClientId *id = g_new0(_ClientId, 1);

    id->service_name = g_strdup(service_name);
    id->local.name = g_strdup(unique_name);
    _LSTransportClientRef(client);
    id->client = client;
    id->is_monitor = false;

    return id;
}

/**
 ********************************************************************************
 * @brief Free a client id.
 *
 * @param  id   IN  client id to free
 ********************************************************************************/
void
_LSHubClientIdLocalFree(_ClientId *id)
{
    LS_ASSERT(id != NULL);
    LS_ASSERT(id->ref == 0);

    g_free(id->service_name);
    g_free(id->local.name);
    _LSTransportClientUnref(id->client);

    if (id->categories)
        g_hash_table_destroy(id->categories);

#ifdef MEMCHECK
    memset(id, 0xFF, sizeof(_ClientId));
#endif

    g_free(id);
}

/**
 ********************************************************************************
 * @brief Allocate memory for a new client id with ref count of 1.
 *
 * @param  service_name     IN  name of service provided by client (or NULL)
 * @param  unique_name      IN  unique name of client
 * @param  client           IN  underlying transport client
 *
 * @retval  client on success
 * @retval  NULL on failure
 ********************************************************************************/
_ClientId*
_LSHubClientIdLocalNewRef(const char *service_name, const char *unique_name, _LSTransportClient *client)
{
    _ClientId *id = _LSHubClientIdLocalNew(service_name, unique_name, client);

    id->ref = 1;

    return id;
}

/**
 ********************************************************************************
 * @brief Increment ref count of client id.
 *
 * @param  id   IN  client id
 ********************************************************************************/
void
_LSHubClientIdLocalRef(_ClientId *id)
{
    LS_ASSERT(id != NULL);
    LS_ASSERT(g_atomic_int_get(&id->ref) > 0);

    g_atomic_int_inc(&id->ref);

    LOG_LS_DEBUG("%s: %d (%p)\n", __func__, id->ref, id);
}

/**
 ********************************************************************************
 * @brief Decrement ref count of client id.
 *
 * @param  id   IN  client id
 ********************************************************************************/
void
_LSHubClientIdLocalUnref(_ClientId *id)
{
    LS_ASSERT(id != NULL);
    LS_ASSERT(g_atomic_int_get(&id->ref) > 0);

    if (g_atomic_int_dec_and_test(&id->ref))
    {
        LOG_LS_DEBUG("%s: %d (%p)\n", __func__, id->ref, id);
        _LSHubClientIdLocalFree(id);
    }
    else
    {
        LOG_LS_DEBUG("%s: %d (%p)\n", __func__, id->ref, id);
    }
}

void
_LSHubClientIdLocalUnrefVoid(void *id)
{
    _LSHubClientIdLocalUnref((_ClientId*) id);
}

/// @} END OF GROUP LunaServiceHub
/// @endcond