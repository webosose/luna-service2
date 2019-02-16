// Copyright (c) 2008-2019 LG Electronics, Inc.
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


#include <string.h>
#include <pbnjson.h>

#include "transport.h"
#include "transport_priv.h"
#include "transport_utils.h"
#include "log.h"
//#include "transport_client.h"
void DumpToFileTransportClient(const char* filename, const char* dump, _LSTransportClient *client)
{
    if (!filename) return;
    char full_path[256] = {0};
    strcpy(full_path, "/tmp/");
    strcat(full_path, filename);
    const char* file_name = _LSTransportClientGetServiceName(client);
    if (file_name && strlen(file_name) > 0)
    {
        strcat(full_path, "_");
        strcat(full_path, file_name);
    }

    FILE *fp;
    // open file for writing 
    fp = fopen (full_path, "w"); 
    if (fp == NULL) 
    {
        //fprintf(stderr, "\nError opend file\n"); 
        return;
    }
    fprintf(fp, file_name);
    fprintf(fp, "\n");
    fprintf (fp, dump);
    fclose(fp);
}
/**
 * @cond INTERNAL
 * @defgroup LunaServiceTransportClient Transport client
 * @ingroup LunaServiceTransport
 * @{
 */

/**
 *******************************************************************************
 * @brief Allocate a new client.
 *
 * @param  transport        IN  transport
 * @param  fd               IN  fd
 * @param  service_name     IN  client service name
 * @param  unique_name      IN  client unique name
 * @param  outgoing         IN  outgoing queue (NULL means allocate)
 *
 * @retval client on success
 * @retval NULL on failure
 *******************************************************************************
 */
_LSTransportClient*
_LSTransportClientNew(_LSTransport* transport, int fd, const char *service_name, const char *unique_name, _LSTransportOutgoing *outgoing)
{
    _LSTransportClient *new_client = g_slice_new0(_LSTransportClient);

    //new_client->sh = sh;
    new_client->service_name = g_strdup(service_name);
    new_client->unique_name = g_strdup(unique_name);
    new_client->app_id = NULL;
    new_client->transport = transport;
    new_client->state = _LSTransportClientStateInvalid;
    new_client->is_dynamic = false;

    if (!_LSTransportChannelInit(&new_client->channel, fd, transport->source_priority))
        goto error;

    new_client->cred = _LSTransportCredNew();

    /* Get pid, gid, and uid of client. */
    LSError lserror;
    LSErrorInit(&lserror);

    if (!_LSTransportGetCredentials(fd, new_client->cred, &lserror))
    {
        LOG_LSERROR(MSGID_LS_TRANSPORT_NETWORK_ERR, &lserror);
        LSErrorFree(&lserror);
    }

    if (outgoing)
    {
        new_client->outgoing = outgoing;
    }
    else
    {
        new_client->outgoing = _LSTransportOutgoingNew();
        if (!new_client->outgoing)
        {
            LOG_LS_ERROR(MSGID_LS_TRANSPORT_INIT_ERR, 0, "Could not allocate outgoing queue");
            goto error;
        }
    }

    new_client->incoming = _LSTransportIncomingNew();
    if (!new_client->incoming)
    {
        LOG_LS_ERROR(MSGID_LS_TRANSPORT_INIT_ERR, 0, "Could not allocate incoming queue");
        goto error;
    }

    return new_client;

error:

    g_free(new_client->service_name);
    g_free(new_client->unique_name);

    if (new_client->outgoing && !outgoing)
    {
        _LSTransportOutgoingFree(new_client->outgoing);
    }
    if (new_client->incoming)
    {
        _LSTransportIncomingFree(new_client->incoming);
    }
    if (new_client->cred)
        _LSTransportCredFree(new_client->cred);

    g_slice_free(_LSTransportClient, new_client);

    return NULL;
}

/**
 *******************************************************************************
 * @brief Free a client.
 *
 * @param  client   IN  client
 *******************************************************************************
 */
void
_LSTransportClientFree(_LSTransportClient* client)
{
    g_free(client->unique_name);
    g_free(client->service_name);
    g_free(client->app_id);
    g_free(client->security_required_groups);
    _LSTransportCredFree(client->cred);
    _LSTransportOutgoingFree(client->outgoing);
    _LSTransportIncomingFree(client->incoming);
    _LSTransportChannelClose(&client->channel, true);
    _LSTransportChannelDeinit(&client->channel);

#ifdef MEMCHECK
    memset(client, 0xFF, sizeof(_LSTransportClient));
#endif

    g_slice_free(_LSTransportClient, client);
}

/**
 *******************************************************************************
 * @brief Allocate a new client with a ref count of 1.
 *
 * @param  transport        IN  transport
 * @param  fd               IN  fd
 * @param  service_name     IN  client service name
 * @param  unique_name      IN  client unique name
 * @param  outgoing         IN  outgoing queue (NULL means allocate)
 *
 * @retval client on success
 * @retval NULL on failure
 *******************************************************************************
 */
_LSTransportClient*
_LSTransportClientNewRef(_LSTransport* transport, int fd, const char *service_name, const char *unique_name, _LSTransportOutgoing *outgoing)
{
    _LSTransportClient *client = _LSTransportClientNew(transport, fd, service_name, unique_name, outgoing);
    if (client)
    {
        client->ref = 1;
        LOG_LS_DEBUG("%s: %d (%p)\n", __func__, client->ref, client);
    }


    return client;
}

/**
 *******************************************************************************
 * @brief Increment the ref count of a client.
 *
 * @param  client   IN  client
 *******************************************************************************
 */
void
_LSTransportClientRef(_LSTransportClient *client)
{
    LS_ASSERT(client != NULL);
    LS_ASSERT(g_atomic_int_get(&client->ref) > 0);

    g_atomic_int_inc(&client->ref);

    LOG_LS_DEBUG("%s: %d (%p)\n", __func__, client->ref, client);
}

/**
 *******************************************************************************
 * @brief Decrement the ref count of a client.
 *
 * @param  client   IN  client
 *******************************************************************************
 */
void
_LSTransportClientUnref(_LSTransportClient *client)
{
    LS_ASSERT(client != NULL);
    LS_ASSERT(g_atomic_int_get(&client->ref) > 0);

    if (g_atomic_int_dec_and_test(&client->ref))
    {
        LOG_LS_DEBUG("%s: %d (%p)\n", __func__, client->ref, client);
        _LSTransportClientFree(client);
    }
    else
    {
        LOG_LS_DEBUG("%s: %d (%p)\n", __func__, client->ref, client);
    }
}

void
_LSTransportClientDetach(_LSTransportClient *client)
{
    LS_ASSERT(client);

    _LSTransportChannel *channel = &client->channel;

    if (channel->recv_watch)
    {
        _LSTransportChannelRemoveReceiveWatch(channel);
    }

    if (channel->send_watch)
    {
        _LSTransportChannelRemoveSendWatch(channel);
    }

    if (channel->accept_watch)
    {
        _LSTransportChannelRemoveAcceptWatch(channel);
    }
}

/**
 *******************************************************************************
 * @brief Get a client's unique name.
 *
 * @param  client   IN  client
 *
 * @retval  name on success
 * @retval  NULL on failure
 *******************************************************************************
 */
const char*
_LSTransportClientGetUniqueName(const _LSTransportClient *client)
{
    LS_ASSERT(client != NULL);
    return client->unique_name;
}

/**
 *******************************************************************************
 * @brief Set a client's unique name.
 *
 * @param  client   IN  client
 * @param  unique_name IN unique name to remember
 *
 *******************************************************************************
 */
void _LSTransportClientSetUniqueName(_LSTransportClient *client, char *unique_name)
{
    LS_ASSERT(client != NULL);
    g_free(client->unique_name);
    client->unique_name = unique_name;
}

/**
 *******************************************************************************
 * @brief Get a client's application Id.
 *
 * @param  client   IN  client
 *
 * @retval  name on success
 * @retval  NULL if client isn't associated with application Id
 *******************************************************************************
 */
const char*
_LSTransportClientGetApplicationId(const _LSTransportClient *client)
{
    LS_ASSERT(client != NULL);
    return client->app_id;
}

/**
 *******************************************************************************
 * @brief Set a client's trust level.
 *
 * @param  client   IN  client
 * @param  app_id IN trust level of client
 *
 *******************************************************************************
 */
void _LSTransportClientSetTrustString(_LSTransportClient *client, const char *trust)
{
    LS_ASSERT(client != NULL);
    g_free(client->trust_level_string);
    client->trust_level_string = g_strdup(trust);
}

/**
 *******************************************************************************
 * @brief Set a client's application Id.
 *
 * @param  client   IN  client
 * @param  app_id IN application Id name to set
 *
 *******************************************************************************
 */
void _LSTransportClientSetApplicationId(_LSTransportClient *client, const char *app_id)
{
    LS_ASSERT(client != NULL);
    g_free(client->app_id);
    client->app_id = g_strdup(app_id);
}

/**
 *******************************************************************************
 * @brief Get a client's service name.
 *
 * @param  client   IN  client
 *
 * @retval name on success
 * @retval NULL on failure
 */
const char*
_LSTransportClientGetServiceName(const _LSTransportClient *client)
{
    LS_ASSERT(client != NULL);
    return client->service_name;
}

const char*
 _LSTransportClientGetTrustString(const _LSTransportClient *client)
{
    LS_ASSERT(client != NULL);
    return client->trust_level_string;
}

/**
 *******************************************************************************
 * @brief Get the channel associated with this client. Does not ref count the
 * channel.
 *
 * @param  client   IN  client
 *
 * @retval  channel
 *******************************************************************************
 */
_LSTransportChannel*
_LSTransportClientGetChannel(_LSTransportClient *client)
{
    LS_ASSERT(client != NULL);
    return &client->channel;
}

const char*
_LSTransportClientGetTrust(const _LSTransportClient *client)
{
    LS_ASSERT(client != NULL);

    if(client->transport->trust_as_string)
        LOG_LS_DEBUG("[%s] trust: %s \n", __func__, client->transport->trust_as_string);

    return client->transport->trust_as_string;
}


_LSTransport*
_LSTransportClientGetTransport(const _LSTransportClient *client)
{
    LS_ASSERT(client != NULL);
    return client->transport;
}

/**
 *******************************************************************************
 * @brief Get credentials for the client.
 *
 * @param  client   IN  client
 *
 * @retval  credentials on success
 * @retval  NULL on failure
 *******************************************************************************
 */
const _LSTransportCred*
_LSTransportClientGetCred(const _LSTransportClient *client)
{
    LS_ASSERT(client != NULL);
    return client->cred;
}

/**
 *******************************************************************************
 * @brief If service should accept inbound calls from the client.
 *
 * @param  client   IN  client
 *
 * @retval  true if allowed, otherwise false
 *******************************************************************************
 */
bool _LSTransportClientAllowInboundCalls(const _LSTransportClient *client)
{
    return client->permissions & _LSClientAllowInbound;
}

/**
 *******************************************************************************
 * @brief If service is allowed to make calls to the client.
 *
 * @param  client   IN  client
 *
 * @retval  true if allowed, otherwise false
 *******************************************************************************
 */
bool _LSTransportClientAllowOutboundCalls(const _LSTransportClient *client)
{
    return client->permissions & _LSClientAllowOutbound;
}

/**
 * @brief  Initialize mask for required groups by client
 *
 * @param  client       IN  Client transport
 * @param  groups_json  IN  JSON string - array of strings, a string - security group. Example:
 *                          ["camera", "torch"]
 *
 * @retval true on success
 */
bool
_LSTransportClientInitializeSecurityGroups(_LSTransportClient *client, const char *groups_json)
{
    LS_ASSERT(client);
    LS_ASSERT(groups_json);
    JSchemaInfo schemaInfo;
    jschema_info_init(&schemaInfo, jschema_all(), NULL, NULL);

    jvalue_ref jgroups = jdom_parse(j_str_to_buffer(groups_json, strlen(groups_json)), DOMOPT_NOOPT, &schemaInfo);
    if (!jis_array(jgroups))
    {
        LOG_LS_ERROR(MSGID_LS_INVALID_JSON, 1,
                     PMLOGKS("JSON", groups_json),
                     "Fail to read JSON: %s. Not array\n", groups_json);
        j_release(&jgroups);
        return false;
    }

    size_t mask_size = client->transport->security_mask_size;
    GHashTable *group_code_map = client->transport->group_code_map;

    LSTransportBitmaskWord *mask = g_malloc0_n(mask_size, sizeof(LSTransportBitmaskWord));
    ssize_t arr_sz = jarray_size(jgroups);
    ssize_t i = 0;
    for (; i < arr_sz; i++)
    {
        jvalue_ref jgroup = jarray_get(jgroups, i);
        const char *group = jstring_get_fast(jgroup).m_str;

        gpointer value = NULL;
        if (g_hash_table_lookup_extended(group_code_map, group, NULL, &value)) {
            BitMaskSetBit(mask, GPOINTER_TO_INT(value));
        }
    }

    client->security_required_groups = mask;

    j_release(&jgroups);
    return true;
}

/**
 * @brief  Initialize mask for required trust by client
 *
 * @param  client       IN  Client transport
 * @param  groups_json  IN  JSON string - array of strings, a string - security group. Example:
 *                          ["camera", "torch"]
 *
 * @retval true on success
 */
bool _LSTransportClientInitializeTrustLevel(_LSTransportClient *client, const char *trust_level) {
    // Now all the services will not have required groups mentioned
    // hence we follow thru onlyf iff groups are mentioned
    if (!trust_level && strlen(trust_level) == 0)
        return true;

    LOG_LS_DEBUG("[%s] client service name : %s, client trasport service name : %s trsut_level: %s \n",
             __func__, client->service_name, client->transport->service_name, trust_level);

    LS_ASSERT(client);
    LS_ASSERT(trust_level);
    client->trust_level_string = g_strdup(trust_level);
    return true;
}
/**
 * @} END OF LunaServiceTransportClient
 * @endcond
 */
