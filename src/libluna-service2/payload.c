// Copyright (c) 2015-2018 LG Electronics, Inc.
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

#include "luna-service2/payload.h"

#include <unistd.h>

#include <glib.h>
#include <pbnjson.h>

#include "error.h"
#include "payload_internal.h"

/**
 * @cond INTERNAL
 * @addtogroup LunaServiceInternals
 * @{
 */

void*
_LSPayloadSerialize(void *data, const LSPayload* payload)
{
    //format: data +
    //        string indentifier + nil +
    //        payload data

    char *ptr = data;

    int size = strlen(payload->type) + 1;
    memcpy(ptr, payload->type, size);
    ptr += size;

    memcpy(ptr, payload->data, payload->size);
    ptr += payload->size;

    return ptr;
}

void
_LSPayloadDeserialize(LSPayload *payload, void *data, size_t size)
{
    size_t type_size = strlen(data) + 1;

    payload->type = data;
    payload->data = (char*)data + type_size;
    payload->size = size - type_size;
}

/**
 * @} END OF LunaServiceInternals
 * @endcond
*/

/**
*******************************************************************************
* @brief Create LSPayload from string
*
* @note String should outlive created payload.
*
* @param json - string represination of json
*
* @retval A new LSPayload structure.
*******************************************************************************
*/
LSPayload *
LSPayloadFromJson(const char *json)
{
    return LSPayloadFromData(PAYLOAD_TYPE_JSON, (void*)json, strlen(json) + 1);
}

/**
*******************************************************************************
* @brief Create LSPayload from jvalue.
*
* @note jvalue should outlive created payload.
*
* @param value - pbnjson representation of json
*
* @retval A new LSPayload structure.
*******************************************************************************
*/
LSPayload *
LSPayloadFromJValue(jvalue_ref value)
{
    const char *json = jvalue_stringify(value);
    return LSPayloadFromData(PAYLOAD_TYPE_JSON, (void*)json, strlen(json) + 1);
}

/**
*******************************************************************************
* @brief Create LSPayload from binary data
*
* @note Binary data should outlive created payload.
*
* @param type - string identifier of binary data type
* @param data - pointer to binary data
* @param size - size of binary data
*
* @retval A new LSPayload structure.
*******************************************************************************
*/
LSPayload *
LSPayloadFromData(const char* type, void* data, size_t size)
{
    LS_ASSERT(type != NULL && data != NULL && size != 0);

    LSPayload *payload = g_new0(LSPayload, 1);

    payload->type = type;
    payload->size = size;
    payload->data = data;

    payload->fd = -1;

    return payload;
}

/**
 * @brief Free payload and its internal data
 *
 * @param payload - a LSPayload
*/
void LSPayloadFree(LSPayload *payload)
{
    LS_ASSERT(payload != NULL);

#ifdef MEMCHECK
    memset(payload, 0xFF, sizeof(LSPayload));
#endif
    g_free(payload);
}

/**
*******************************************************************************
* @brief Attach file descriptor to passed LSPayload
*
* @note File descriptor should outlive created payload
*
* @param payload - a LSPayload
* @param fd - File descriptor to attach
*******************************************************************************
*/
void LSPayloadAttachFd(LSPayload *payload, int fd)
{
    LS_ASSERT(payload != NULL);
    payload->fd = fd;
}

/**
*******************************************************************************
* @brief Get file descriptor attached to passed LSPayload
*
* @param payload - a LSPayload
*
* @retval File descriptor or -1 if file descriptor is not attached
*******************************************************************************
*/
int
LSPayloadGetFd(const LSPayload *payload)
{
    LS_ASSERT(payload != NULL);

    return payload->fd;
}

/**
*******************************************************************************
* @brief Get string representation of json in LSPayload.
*
* @param payload - a LSPayload
*
* @retval Json string or NULL if string can't be retrieved
*******************************************************************************
*/
const char *
LSPayloadGetJson(const LSPayload *payload)
{
    LS_ASSERT(payload != NULL);

    // TODO:
    // Currently we suppose that we have only string representation of JSON
    // so we return pointer to our data.
    // The cached value should be removed from LSMessage, when all types of
    // messages will support LSPayload
    return (const char*)payload->data;
}

/**
*******************************************************************************
* @brief Get jvalue_ref representation of json in LSPayload.
*
* @param payload - a LSPayload
*
* @retval jvalue_ref or NULL if jvalue_ref can't be retrieved
*******************************************************************************
*/
jvalue_ref
LSPayloadGetJValue(const LSPayload *payload)
{
    LS_ASSERT(payload != NULL);

    // TODO: Currently to be in sync with LSPayloadGetJson we think that our data
    // is json string.
    return jdom_create(j_cstr_to_buffer((const char*)payload->data), jschema_all(), NULL);
}

/**
*******************************************************************************
* @brief Get string identifier of LSPayload data.
*
* @param payload - a LSPayload
*
* @retval String identifier
*******************************************************************************
*/
const char*
LSPayloadGetDataType(const LSPayload *payload)
{
    LS_ASSERT(payload != NULL);

    return payload->type;
}

/**
*******************************************************************************
* @brief Get raw LSPayload data.
*
* @param payload - a LSPayload
* @param size    - pointer to size_t in which size of data will be stored
*
* @retval Pointer to data.
*******************************************************************************
*/
void*
LSPayloadGetData(const LSPayload *payload, size_t* size)
{
    LS_ASSERT(payload != NULL && size != NULL);

    *size = payload->size;
    return payload->data;
}
