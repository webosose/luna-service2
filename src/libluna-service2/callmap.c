// Copyright (c) 2008-2021 LG Electronics, Inc.
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


#include <glib.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <stdlib.h>
#include <regex.h>

#include <pbnjson.h>

#include <luna-service2/lunaservice.h>
#include <luna-service2/lunaservice-errors.h>

#include "simple_pbnjson.h"
#include "transport.h"
#include "transport_message.h"
#include "transport_priv.h"
#include "message.h"
#include "base.h"
#include "category.h"
#include "transport_utils.h"
#include "clock.h"
#include "pmtrace_ls2.h"
#include "uri.h"

/**
 * @cond INTERNAL
 * @addtogroup LunaServiceClientInternals
 * @{
 */

static bool _LSCallFromApplicationCommon(LSHandle *sh, const char *uri,
       const char *payload,
       const char *applicationID,
       LSFilterFunc callback, void *ctx,
       LSMessageToken *ret_token, bool single, LSError *lserror);

typedef GArray _TokenList;

static _TokenList *
_TokenListNew()
{
    return g_array_new(false, false, sizeof(LSMessageToken));
}

static void
_TokenListFree(_TokenList *tokens)
{
    g_array_free(tokens, true);
}

static int
_TokenListLen(_TokenList *tokens)
{
    if (!tokens) return 0;
    return tokens->len;
}

static void
_TokenListAddList(_TokenList *tokens, _TokenList *data)
{
    if (tokens && data)
        g_array_append_vals(tokens, data->data, data->len);
}

static void
_TokenListAdd(_TokenList *tokens, LSMessageToken t)
{
    if (tokens) g_array_append_val(tokens, t);
}

static void
_TokenListRemove(_TokenList *tokens, LSMessageToken t)
{
    if (!tokens) return;

    int i;
    for (i = 0; i < tokens->len; i++)
    {
        LSMessageToken iter = g_array_index(tokens, LSMessageToken, i);
        if (iter == t)
        {
            g_array_remove_index_fast(tokens, i);
            break;
        }
    }
}

typedef struct _ServerStatus
{
    LSServerStatusFunc callback;
    void              *ctx;
    LSMessageToken     token;
} _ServerStatus;

typedef struct _ServerInfo
{
    bool ServiceStatusChanged;
    char *serviceName;
    bool connected;
} _ServerInfo;

struct _CallMap {

    GHashTable *tokenMap;      //< Map from token to _Call
    GHashTable *signalMap;     //< Map from signal key to list of tokens
    GHashTable *serviceMap;    //< Map from serviceName to list of tokens

    //DBusHandleMessageFunction message_handler;

    pthread_mutex_t  lock;
};

void
_CallMapLock(_CallMap *map)
{
    int pthread_mutex_lock_ret = pthread_mutex_lock(&map->lock);
    LS_ASSERT(pthread_mutex_lock_ret == 0);
}

void
_CallMapUnlock(_CallMap *map)
{
    int pthread_mutex_unlock_ret = pthread_mutex_unlock(&map->lock);
    LS_ASSERT(pthread_mutex_unlock_ret == 0);
}

//static DBusHandlerResult _message_filter(DBusConnection *conn, DBusMessage *msg, void *ctx);

enum {
    CALL_TYPE_INVALID,
    CALL_TYPE_METHOD_CALL,
    CALL_TYPE_SIGNAL,
    CALL_TYPE_SIGNAL_SERVER_STATUS,
};

typedef struct _Call {

    int           ref;
    char         *serviceName;
#ifdef HAS_LTTNG
    char         *methodName;
#endif
    LSHandle     *sh;          //< back pointer to the service handle (non-owning)
    LSFilterFunc  callback;

    void         *ctx;         //< user context

    LSMessageToken token;      //< key used in callmap->tokenMap

    int            type;

    bool           single;

    /* Signal specific (we may want to break this
     * out into a separate struct) */
    //char          *rule;
    char          *signal_method;   //< registered signal method (could be NULL)
    char          *signal_category; //< registered signal category (required)
    char          *match_key;  //<key used in callmap->signalMap
    struct        timespec time;  //< time value for performance measurement
    GSource       *timer_source; //< source for timer expiration (non-NULL if set)

    int           timeout_ms;  //< milliseconds to timeout before next message reply.

    bool          is_connected;  //< Connection status of the service. Is valid only for server status signals

    pthread_mutex_t lock;
} _Call;


_Call *
_CallNew(LSHandle *sh, int type, const char *serviceName,
         LSFilterFunc callback, void *ctx,
         LSMessageToken token, const char *methodName)
{
    _Call *call = g_new0(_Call, 1);

    call->sh = sh;
    call->serviceName = g_strdup(serviceName);
    call->callback = callback;
    call->ctx = ctx;
    call->token = token;
    call->type = type;
#ifdef HAS_LTTNG
    call->methodName = g_strdup(methodName);
#endif

    int res;
    pthread_mutexattr_t ma;
    pthread_mutexattr_init(&ma);
    res = pthread_mutexattr_settype(&ma, PTHREAD_MUTEX_RECURSIVE);
    LS_ASSERT(res == 0);
    res = pthread_mutex_init(&call->lock, &ma);
    LS_ASSERT(res == 0);
    pthread_mutexattr_destroy(&ma);

    return call;
}

void
_CallFree(_Call *call)
{
    if (!call) return;

    if (call->timer_source != NULL)
    {
        g_source_destroy(call->timer_source);
        g_source_unref(call->timer_source);
    }
    g_free(call->serviceName);
    //g_free(call->rule);
    g_free(call->signal_method);
    g_free(call->signal_category);
    g_free(call->match_key);

#ifdef HAS_LTTNG
    g_free(call->methodName);
#endif

    pthread_mutex_destroy(&call->lock);

#ifdef MEMCHECK
    memset(call, 0xFF, sizeof(_Call));
#endif

    g_free(call);
}

void _CallDebug(_Call* call, const char* uri, const char* payload)
{
    if (call)
    {
        if (DEBUG_VERBOSE)
        {
            LOG_LS_DEBUG("TX: LSCall token <<%ld>> %s %s", call->token, uri, payload);
        }
        else
        {
            ClockGetTime(&call->time);
            LOG_LS_DEBUG("TX: LSCall token <<%ld>> %s", call->token, uri);
        }
    }
    else
    {
        LOG_LS_DEBUG("TX: LSCall no token");
    }
}

static bool
_service_watch_disable(LSHandle *sh, _Call *call)
{
    if (CALL_TYPE_SIGNAL_SERVER_STATUS == call->type && call->serviceName)
    {
        return LSTransportUnregisterSignalServiceStatus(sh->transport, call->serviceName, sh->is_public_bus, NULL, NULL);
    }
    return false;
}

static void ResetCallTimeout(_Call *call);

/**
 *******************************************************************************
 * @brief Insert a call into the callmap.
 *
 * @param map
 * @param call
 * @param single
 * @param lserror
 *
 * @return true on success, otherwise false
 *******************************************************************************
 */
static bool
_CallInsert(_CallMap *map, _Call *call, bool single,
            LSError *lserror)
{
    // TODO: Remove default branch and add parameter checking with assertion,
    // as far, as we have only one 'true' case.
    GHashTable *table = NULL;
    gpointer    key = NULL;

    switch (call->type)
    {
    case CALL_TYPE_METHOD_CALL:
    case CALL_TYPE_SIGNAL_SERVER_STATUS:
        table = map->serviceMap;
        key   = call->serviceName;
        break;
    case CALL_TYPE_SIGNAL:
        table = map->signalMap;
        key   = call->match_key;
        break;
    default:
        _LSErrorSet(lserror, MSGID_LS_INVALID_CALL, -1, "Unsupported call type.");
        return false;
    }

    call->single = single;

    // TODO: LS_ASSERT(call->ref == 0);
    call->ref = 1;

    _TokenList *token_list = g_hash_table_lookup(table, key);
    if (_TokenListLen(token_list) == 0)
    {
        if (!token_list)
        {
            token_list = _TokenListNew();

            g_hash_table_replace(table, g_strdup(key), token_list);
        }
    }

    _TokenListAdd(token_list, call->token);

    /* It's an error if the key is already in the map */
    LS_ASSERT(g_hash_table_lookup(map->tokenMap, (gpointer)call->token) == NULL);

    g_hash_table_replace(map->tokenMap, (gpointer)call->token, call);

    return true;
}

static void
_CallRemove(_CallMap *map, _Call *call)
{
    _CallMapLock(map);

    _Call *orig_call = g_hash_table_lookup(map->tokenMap, (gpointer)call->token);
    if (orig_call == call)
    {
        GHashTable *table = NULL;
        gpointer    key = NULL;

        if (call->timer_source != NULL)
        {
            call->timeout_ms = 0;
            ResetCallTimeout(call);
        }
        switch(call->type)
        {
        case CALL_TYPE_METHOD_CALL:
        case CALL_TYPE_SIGNAL_SERVER_STATUS:
            if (call->serviceName)
            {
                table = map->serviceMap;
                key   = call->serviceName;
            }
            break;
        case CALL_TYPE_SIGNAL:
            if (call->match_key)
            {
                table = map->signalMap;
                key   = call->match_key;
            }
            break;
        }
        if (table) {
            _TokenList *token_list = g_hash_table_lookup(table, key);

            _TokenListRemove(token_list, call->token);
            if (token_list != NULL && _TokenListLen(token_list) == 0) {
                g_hash_table_remove(table, key);
            }
        }
        g_hash_table_remove(map->tokenMap, (gpointer)call->token);
    }

    /* <eeh> TODO: what does the else case mean (i.e., orig_call != call) */

    _CallMapUnlock(map);
}

static void
_CallAddReference(_Call *call)
{
    LS_ASSERT(g_atomic_int_get (&call->ref) > 0);
    g_atomic_int_inc(&call->ref);
}

static void
_CallLock(_Call *call)
{
    pthread_mutex_lock(&call->lock);
}

static void
_CallUnlock(_Call *call)
{
    pthread_mutex_unlock(&call->lock);
}

static _Call*
_CallAcquireEx(_CallMap *map, LSMessageToken token, bool lock)
{
    _Call *call;

    _CallMapLock(map);

    call = g_hash_table_lookup(map->tokenMap, (gpointer)token);
    if (call)
    {
        _CallAddReference(call);
        if (lock)
            _CallLock(call);
    }

    _CallMapUnlock(map);

    return call;
}

static void
_CallReleaseUnsafe(_Call *call)
{
    LS_ASSERT(g_atomic_int_get (&call->ref) > 0);

    if (g_atomic_int_dec_and_test(&call->ref))
    {
        _CallFree(call);
    }
}

static _Call*
_CallAcquire(_CallMap *map, LSMessageToken token)
{
    return _CallAcquireEx(map, token, true);
}

static void
_CallRelease(_Call *call)
{
    _CallUnlock(call);
    _CallReleaseUnsafe(call);
}

/**
 *******************************************************************************
 * @brief Initialize callmap.
 *
 * @param sh
 * @param *ret_map
 * @param lserror
 *
 * @return true on success, otherwise false
 *******************************************************************************
 */
bool
_CallMapInit(LSHandle *sh, _CallMap **ret_map, LSError *lserror)
{
    _CallMap *map = g_new0(_CallMap, 1);

    map->tokenMap = g_hash_table_new_full(g_direct_hash, g_direct_equal,
                    NULL, (GDestroyNotify)_CallReleaseUnsafe);
    map->signalMap = g_hash_table_new_full(g_str_hash, g_str_equal,
                    (GDestroyNotify)g_free, (GDestroyNotify)_TokenListFree);
    map->serviceMap = g_hash_table_new_full(g_str_hash, g_str_equal,
                    (GDestroyNotify)g_free, (GDestroyNotify)_TokenListFree);

    if (pthread_mutex_init(&map->lock, NULL))
    {
        _LSErrorSet(lserror, MSGID_LS_MUTEX_ERR, -1, "Could not initialize mutex.");
        goto error;
    }

    *ret_map = map;
    return true;

error:
    _CallMapDeinit(sh, map);
    return false;
}

/**
 *******************************************************************************
 * @brief Deinitialize call map.
 *
 * @param sh
 * @param map
 *******************************************************************************
 */
void
_CallMapDeinit(LSHandle *sh, _CallMap *map)
{
    if (map)
    {
        g_hash_table_destroy(map->signalMap);
        g_hash_table_destroy(map->serviceMap);

        //Destroy set timers for all remaining calls if any
        GHashTableIter iter;
        gpointer key, value;
        g_hash_table_iter_init(&iter, map->tokenMap);
        while (g_hash_table_iter_next(&iter, &key, &value))
        {
            _Call * call = (_Call *)value;
            if (call->timer_source != NULL)
            {
                call->timeout_ms = 0;
                ResetCallTimeout(call);
            }
        }
        g_hash_table_destroy(map->tokenMap);

        if (pthread_mutex_destroy(&map->lock))
        {
            LOG_LS_WARNING(MSGID_LS_MUTEX_ERR, 0, "Could not destroy mutex &map->lock");
        }

        g_free(map);
    }
}

static void
_LSMessageSetFromError(_LSTransportMessage *transport_msg, _Call *call, LSMessage *reply)
{
    const char *error_text = NULL;

    LS_ASSERT(_LSTransportMessageIsErrorType(transport_msg));

    reply->category = LUNABUS_ERROR_CATEGORY;

    /* TODO: equivalent for DBUS_ERROR_SERVICE_UNKNOWN */
    switch (_LSTransportMessageGetType(transport_msg))
    {
    /* generic error */
    case _LSTransportMessageTypeError:
    {
        reply->methodAllocated =
                 g_strdup_printf("%s", LUNABUS_ERROR_UNKNOWN_ERROR);
        reply->method = reply->methodAllocated;
        //error_text = g_strdup("Unknown error");
        error_text = _LSTransportMessageGetError(transport_msg);
        break;
    }

    case _LSTransportMessageTypeErrorUnknownMethod:
    {
        reply->method = LUNABUS_ERROR_UNKNOWN_METHOD;
        //error_text = g_strdup_printf("Method \"%s\" doesn't exist", _LSTransportMessageGetError(msg));
        error_text = _LSTransportMessageGetError(transport_msg);
        break;
    }

    default:
    {
        LOG_LS_ERROR(MSGID_LS_NOT_AN_ERROR, 0,
                     "%s: The message type %d is not an error type", __func__, _LSTransportMessageGetType(transport_msg));
        LS_ASSERT(0);
    }
    }

    /* Escape the string */
    if (!reply->payload)
    {
        if (!error_text) goto error;

        char *escaped = g_strescape(error_text, NULL);

        if (!escaped) goto error;

        reply->payloadAllocated = g_strdup_printf(
            "{\"returnValue\":false,\"errorCode\":-1,\"errorText\":\"%s\"}",
            escaped);
        reply->payload = reply->payloadAllocated;

        g_free(escaped);
    }

    return;

error:
    g_free(reply->methodAllocated);
    g_free(reply->payloadAllocated);

    reply->category = LUNABUS_ERROR_CATEGORY;
    reply->method = LUNABUS_ERROR_OOM;

    reply->payloadAllocated = NULL;
    reply->payload =
        "{\"returnValue\":false,\"errorCode\":-1,\"errorText\":\"OOM\"}";
}

void
_LSMessageTranslateFromCall(_Call *call, LSMessage *reply,
                            _ServerInfo *server_info)
{

    _LSTransportMessage *msg = reply->transport_msg;
    _LSTransportMessageType type = _LSTransportMessageGetType(msg);

    reply->responseToken = call->token;

    switch (type)
    {
    case _LSTransportMessageTypeReply:
    case _LSTransportMessageTypeReplyWithFd:
        {
        /* translate signal ack to lunabus ack */
        switch (call->type)
        {
            case CALL_TYPE_SIGNAL:
                if (g_strcmp0(_LSTransportMessageGetPayload(msg), "{\"returnValue\":true}") == 0)
                {
                    reply->category = LUNABUS_SIGNAL_CATEGORY;
                    reply->method = LUNABUS_SIGNAL_REGISTERED;
                    reply->payload = "{\"returnValue\":true}";
                }
                break;
        }
        break;
        }
    case _LSTransportMessageTypeSignal:
    case _LSTransportMessageTypeServiceDownSignal:
    case _LSTransportMessageTypeServiceUpSignal:
    {
        if (server_info && server_info->ServiceStatusChanged)
        {
            switch (call->type)
            {
            case CALL_TYPE_METHOD_CALL:
                if (!server_info->connected)
                {
                    reply->category = LUNABUS_ERROR_CATEGORY;
                    reply->method = LUNABUS_ERROR_SERVICE_DOWN;

                    reply->payloadAllocated = g_strdup_printf(
                        "{\"serviceName\":\"%s\","
                         "\"returnValue\":false,"
                         "\"errorCode\":-1,"
                         "\"errorText\":\"%s is not running.\"}",
                        server_info->serviceName,
                        server_info->serviceName);

                    reply->payload = reply->payloadAllocated;
                    reply->serviceDownMessage = true;
                }
                else
                {
                    reply->ignore = true;
                }
                break;
            case CALL_TYPE_SIGNAL_SERVER_STATUS:
                /* Because of the public/private compatibility trickery,
                 * there may come more than one signal about service status.
                 * Thus, we need to carefully track what we reported to the user.
                 * And to ignore duplicate reports.
                 */
                if (call->is_connected != server_info->connected)
                {
                    call->is_connected = server_info->connected;
                    reply->category = LUNABUS_SIGNAL_CATEGORY;
                    reply->method = LUNABUS_SIGNAL_SERVERSTATUS;

                    reply->payloadAllocated = g_strdup_printf(
                        "{\"serviceName\":\"%s\",\"connected\":%s}",
                        server_info->serviceName,
                        server_info->connected ? "true" : "false");

                    reply->payload = reply->payloadAllocated;
                }
                else
                {
                    reply->ignore = true;
                }
                break;
            }
        }
        break;
    }

    /* reply for service name lookup (registerServerStatus) */
    case _LSTransportMessageTypeQueryServiceStatusReply:
    {
        LS_ASSERT(call->type == CALL_TYPE_SIGNAL_SERVER_STATUS);

        /* FIXME -- need getter for this or make GetBody skip over the
         * reply serial */
        /* skip over reply serial to get available value */
        int available = *((int*)(_LSTransportMessageGetBody(msg) + sizeof(LSMessageToken)));

        /* Initialize connection status with the first reply to signal/registerServerStatus */
        call->is_connected = available;

        if (available)
        {
            reply->category = LUNABUS_SIGNAL_CATEGORY;
            reply->method = LUNABUS_SIGNAL_SERVERSTATUS;
            reply->payloadAllocated = g_strdup_printf(
                "{\"serviceName\":\"%s\",\"connected\":true}",
                call->serviceName);
            reply->payload = reply->payloadAllocated;
        }
        else
        {
            reply->category = LUNABUS_SIGNAL_CATEGORY;
            reply->method = LUNABUS_SIGNAL_SERVERSTATUS;
            reply->payloadAllocated = g_strdup_printf(
                "{\"serviceName\":\"%s\",\"connected\":false}",
                call->serviceName);
            reply->payload = reply->payloadAllocated;
        }

        break;
    }

    /* reply for service category query (registerServerCategory) */
    case _LSTransportMessageTypeQueryServiceCategoryReply:
    {
        LS_ASSERT(call->type == CALL_TYPE_SIGNAL);

        _LSTransportMessageIter iter;
        _LSTransportMessageIterInit(msg, &iter);

        LS_ASSERT(_LSTransportMessageIterHasNext(&iter));
        _LSTransportMessageIterNext(&iter);

        const char *categories = NULL;
        _LSTransportMessageGetString(&iter, &categories);

        reply->category = LUNABUS_SIGNAL_CATEGORY;
        reply->method = LUNABUS_SIGNAL_SERVICE_CATEGORY;
        reply->payload = reply->payloadAllocated = g_strdup(categories);

        break;
    }

    /* translate all transport errors to lunabus errors. */
    case _LSTransportMessageTypeError:
    case _LSTransportMessageTypeErrorUnknownMethod:
    {
        _LSMessageSetFromError(msg, call, reply);
        break;
    }

    default:
    {
        LOG_LS_ERROR(MSGID_LS_UNKNOWN_MSG, 0, "Unknown message type: %d", type);
        break;
    }
    }
}

/**
 *******************************************************************************
 * @brief Dispatch a message to each callback in tokens list.
 *
 * Messages can have multiple callbacks in the case of signals and
 * one callback for a message response.
 *
 * @param sh
 * @param tokens
 * @param msg
 * @param server_info
 *
 * @return true on success, otherwise false
 *******************************************************************************
 */
static bool
_handle_reply(LSHandle *sh, _TokenList *tokens, _LSTransportMessage *msg,
              _ServerInfo *server_info)
{
    //DBusHandlerResult result = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    bool ret = true;

    int i;
    int len = tokens->len;
    for (i = 0; i < len; i++)
    {
        LSMessageToken token =
            g_array_index(tokens, LSMessageToken, i);

        _Call *call = _CallAcquire(sh->callmap, token);

        if (!call)
        {
            continue;
        }

        ResetCallTimeout(call);

        if (call->callback)
        {
            LSMessage *reply = _LSMessageNewRef(msg, sh);

            // translate non-jsonized bus messages here...
            _LSMessageTranslateFromCall(call, reply, server_info);
            _LSMessageParsePayload(reply);

            // remove call from callmap
            if (reply->serviceDownMessage)
            {
                _CallRemove(sh->callmap, call);
            }
            else if (call->single && !reply->ignore /* NOV-88761 */)
            {
                LSError lserror;
                LSErrorInit(&lserror);

                if (!LSCallCancel(sh, call->token, &lserror))
                {
                    LOG_LSERROR(MSGID_LS_CANT_CANCEL_METH, &lserror);
                    LSErrorFree(&lserror);
                }
            }

            if (!reply->ignore)
            {
                PMTRACE_CLIENT_CALLBACK(sh->name, call->serviceName, call->methodName, token);

                struct timespec current_time, gap_time;
                if (DEBUG_TRACING)
                {
                    ClockGetTime(&current_time);
                    ClockDiff(&gap_time, &current_time, &call->time);
                    LOG_LS_DEBUG("TYPE=method call response time | TIME=%lld | FROM=%s | TO=%s",
                              ClockGetMs(&gap_time), sh->name, call->serviceName);
                }

                // Note: be careful user can call LSUnregister in callback.
                ret = call->callback(sh, reply, call->ctx);

                if (DEBUG_TRACING)
                {
                    ClockGetTime(&current_time);
                    ClockDiff(&gap_time, &current_time, &call->time);
                    LOG_LS_DEBUG("TYPE=client handler execution time | TIME=%lld", ClockGetMs(&gap_time));
                }

                if (!ret)
                {
                    // TODO handle false == DBUS_HANDLER_RESULT_NEED_MEMORY
                }
            }

            LSMessageUnref(reply);
        }

        _CallRelease(call);
    }

    return ret;
}

/* TODO: we should try to integrate this with the non-dbus version of
 * _LSMessageTranslateFromCall */
void
_LSHandleMessageFailure(_LSTransportMessage *message, _LSTransportMessageFailureType failure_type, void *context)
{
    LSHandle *sh = (LSHandle*) context;

    /* acquire call */
    _Call *call = _CallAcquire(sh->callmap, _LSTransportMessageGetToken(message));

    if (!call)
    {
        LOG_LS_DEBUG("_CallAcquire failed");
        return;
    }

    /* assert that call is a method call type */
    if (call->callback)
    {
        LSMessage *reply = _LSMessageNewRef(_LSTransportMessageEmpty(), sh);

        LOG_LS_DEBUG("Calling callback handler with failure message of type %d and service %s",
                     call->type,
                     call->serviceName);

        reply->responseToken = call->token;

        /* construct the error message -- the allocated payload is freed
         * when the message ref count goes to 0 */
        switch (failure_type)
        {

        case _LSTransportMessageFailureTypeNotProcessed:
            reply->category = LUNABUS_ERROR_CATEGORY;
            reply->method = LUNABUS_ERROR_SERVICE_DOWN;
            reply->payloadAllocated = g_strdup_printf(
                "{\"returnValue\":false,"
                 "\"errorCode\":-1,"
                 "\"errorText\":\"Message not processed.\"}");
            reply->payload = reply->payloadAllocated;
            break;

        case _LSTransportMessageFailureTypeUnknown:
            reply->category = LUNABUS_ERROR_CATEGORY;
            reply->method = LUNABUS_ERROR_SERVICE_DOWN;
            reply->payloadAllocated = g_strdup_printf(
                "{\"returnValue\":false,"
                 "\"errorCode\":-1,"
                 "\"errorText\":\"Message status unknown.\"}");
            reply->payload = reply->payloadAllocated;
            break;

        case _LSTransportMessageFailureTypeServiceUnavailable:
            reply->category = LUNABUS_ERROR_CATEGORY;
            reply->method = LUNABUS_ERROR_SERVICE_DOWN;
            reply->payloadAllocated = g_strdup_printf(
                "{\"serviceName\":\"%s\","
                 "\"returnValue\":false,"
                 "\"errorCode\":-1,"
                 "\"errorText\":\"%s is not running.\"}",
                call->serviceName, call->serviceName);
            reply->payload = reply->payloadAllocated;

            /* probably not necessary, since this is just a flag to mark
             * that we should remove this call from the callmap and we
             * always do that here */
            reply->serviceDownMessage = true;

            break;

        case _LSTransportMessageFailureTypePermissionDenied:
            reply->category = LUNABUS_ERROR_CATEGORY;
            reply->method = LUNABUS_ERROR_PERMISSION_DENIED;
            reply->payloadAllocated = g_strdup_printf(
                "{\"returnValue\":false,"
                 "\"errorCode\":-1,"
                 "\"errorText\":\"Not permitted to send to %s.\"}",
                 call->serviceName);
            reply->payload = reply->payloadAllocated;
            break;

        case _LSTransportMessageFailureTypeServiceNotExist:
            reply->category = LUNABUS_ERROR_CATEGORY;
            reply->method = LUNABUS_ERROR_SERVICE_NOT_EXIST;
            reply->payloadAllocated = g_strdup_printf(
                "{\"returnValue\":false,"
                 "\"errorCode\":-1,"
                 "\"errorText\":\"Service does not exist: %s.\"}",
                 call->serviceName);
            reply->payload = reply->payloadAllocated;
            break;

        case _LSTransportMessageFailureTypeMessageContentError:
            reply->category = LUNABUS_ERROR_CATEGORY;
            reply->method = LUNABUS_ERROR_BAD_MESSAGE;
            reply->payloadAllocated = g_strdup_printf(
                "{\"returnValue\":false,"
                 "\"errorCode\":-1,"
                 "\"errorText\":\"Badly formatted message\"}");
            reply->payload = reply->payloadAllocated;
            break;

        default:
            LOG_LS_ERROR(MSGID_LS_UNKNOWN_FAILURE, 1,
                         PMLOGKFV("FLR_TYPE", "%d", failure_type),
                         "Unknown failure_type: %d", failure_type);
            LS_ASSERT(0);
        }

        _LSMessageParsePayload(reply);
        bool ret = call->callback(sh, reply, call->ctx);
        if (!ret)
        {
            // TODO handle false
        }

        _CallRemove(sh->callmap, call);

        LSMessageUnref(reply);
    }

    _CallRelease(call);
}

void _send_not_running(LSHandle *sh, _TokenList *tokens)
{
    int token_list_len = _TokenListLen(tokens);
    int i;

    for (i = 0; i < token_list_len; i++)
    {
        LSMessageToken token = g_array_index(tokens, LSMessageToken, i);

        _Call *call = _CallAcquire(sh->callmap, token);

        if (!call)
        {
            LOG_LS_ERROR(MSGID_LS_NO_TOKEN, 0,
                         "%s: Expected to find call with token: %lu in callmap", __func__, (unsigned long)token);
            continue;
        }

        if (call->type == CALL_TYPE_METHOD_CALL)
        {
            if (call->callback)
            {
                LSMessage *reply = _LSMessageNewRef(_LSTransportMessageEmpty(), sh);

                reply->responseToken = call->token;

                reply->category = LUNABUS_ERROR_CATEGORY;
                reply->method = LUNABUS_ERROR_SERVICE_DOWN;

                reply->payloadAllocated = g_strdup_printf(
                    "{\"serviceName\":\"%s\","
                     "\"returnValue\":false,"
                     "\"errorCode\":-1,"
                     "\"errorText\":\"%s is not running.\"}",
                    call->serviceName, call->serviceName);

                reply->payload = reply->payloadAllocated;

                // fprintf(stderr, "%s: doing callback\n", __func__);
                _LSMessageParsePayload(reply);

                bool ret = call->callback(sh, reply, call->ctx);

                if (!ret)
                {
                    fprintf(stderr, "%s: callback failed\n", __func__);
                }

                LSMessageUnref(reply);
            }

            _CallRemove(sh->callmap, call);

        }

       _CallRelease(call);

    } // for
}

void
_LSDisconnectHandler(_LSTransportClient *client, _LSTransportDisconnectType type, void *context)
{

    LSHandle *sh = (LSHandle *)context;
    _CallMap *map = sh->callmap;

    if (NULL != client->service_name)
    {

        _CallMapLock(map);

        _TokenList *tokens = g_hash_table_lookup(map->serviceMap, client->service_name);

        // copy the list of tokens so we can unlock ASAP
        _TokenList *tokens_copy = _TokenListNew();
        _TokenListAddList(tokens_copy, tokens);

        _CallMapUnlock(map);

        _send_not_running(sh, tokens_copy);
        _TokenListFree(tokens_copy);
    }

    if (NULL != client->unique_name)
    {
        /* Remove client subscriptions from the catalog
         */
        _LSCatalogRemoveClientSubscriptions(sh->catalog, client);
    }
    else
    {
        LOG_LS_WARNING(MSGID_LS_NULL_CLIENT, 0,
                       "Client disconnected before sending client info");
    }
}

/* SERVER_STATUS */
static void
_parse_service_status_signal(_LSTransportMessage *msg, _ServerInfo *server_info)
{
    _LSTransportMessageType type = _LSTransportMessageGetType(msg);

    if (type == _LSTransportMessageTypeServiceDownSignal)
    {
        server_info->ServiceStatusChanged = true;
        server_info->serviceName = LSTransportServiceStatusSignalGetServiceName(msg);
        server_info->connected = false;
    }
    else if (type == _LSTransportMessageTypeServiceUpSignal)
    {
        LOG_LS_DEBUG("ServiceUpSignal");
        server_info->ServiceStatusChanged = true;
        server_info->serviceName = LSTransportServiceStatusSignalGetServiceName(msg);
        server_info->connected = true;
    }
    else
    {
        server_info->ServiceStatusChanged = false;
        server_info->serviceName = NULL;
        server_info->connected = false;
    }
}

/**
 *******************************************************************************
 * @brief Find all tokens that handle this signal message.
 *
 * @param map
 * @param msg
 * @param tokens
 * @param server_info
 *******************************************************************************
 */
static void
_get_signal_tokens(_CallMap *map, _LSTransportMessage *msg, _TokenList *tokens,
                   _ServerInfo *server_info)
{
    const char *category = _LSTransportMessageGetCategory(msg);
    const char *method = _LSTransportMessageGetMethod(msg);

    char *category_key = g_strdup_printf("%s", category);
    char *method_key = g_strdup_printf("%s/%s", category, method);

    _CallMapLock(map);

    _TokenList *category_matches = g_hash_table_lookup(
                    map->signalMap, category_key);
    _TokenList *method_matches = g_hash_table_lookup(
                    map->signalMap, method_key);

    if (server_info->ServiceStatusChanged)
    {
        _TokenList *service_matches =
            g_hash_table_lookup(map->serviceMap,
                                server_info->serviceName);
        _TokenListAddList(tokens, service_matches);
    }

    _TokenListAddList(tokens, category_matches);
    _TokenListAddList(tokens, method_matches);

    _CallMapUnlock(map);

    g_free(category_key);
    g_free(method_key);
}

static void
_get_reply_tokens(_CallMap *map, _LSTransportMessage *msg, _TokenList *tokens)
{
    LSMessageToken tok = _LSTransportMessageGetReplyToken(msg);
    _TokenListAdd(tokens, tok);
}

static void
_get_first_field_tokens(_CallMap *callmap, _LSTransportMessage *msg, _TokenList *tokens)
{
    _LSTransportMessageIter iter;
    _LSTransportMessageIterInit(msg, &iter);
    LSMessageToken tok;
    _Static_assert(sizeof(tok) <= sizeof(int64_t), "LSMessageToken should fit into int64_t");
    _LSTransportMessageGetInt64(&iter, (int64_t *) &tok);
    _TokenListAdd(tokens, tok);
}

void
_MessageFindTokens(_CallMap *callmap, _LSTransportMessage *msg,
                   _ServerInfo *server_info, _TokenList *tokens)
{
    _LSTransportMessageType message_type = _LSTransportMessageGetType(msg);

    /* SERVER_STATUS */
    _parse_service_status_signal(msg, server_info);

    switch (message_type)
    {
    case _LSTransportMessageTypeSignal:
    case _LSTransportMessageTypeServiceDownSignal:
    case _LSTransportMessageTypeServiceUpSignal:
        _get_signal_tokens(callmap, msg, tokens, server_info);
        break;
    case _LSTransportMessageTypeReply:
    case _LSTransportMessageTypeReplyWithFd:
    case _LSTransportMessageTypeQueryServiceStatusReply:
    case _LSTransportMessageTypeError:
    case _LSTransportMessageTypeErrorUnknownMethod:
        _get_reply_tokens(callmap, msg, tokens);
        break;
    case _LSTransportMessageTypeQueryServiceCategoryReply:
        _get_first_field_tokens(callmap, msg, tokens);
        break;
    default:
        LOG_LS_ERROR(MSGID_LS_UNHANDLED_MSG, 1,
                     PMLOGKFV("MSG_TYPE", "%d", message_type),
                     "Unhandled message type: %d", message_type);
        break;
    }
}

/**
 *******************************************************************************
 * @brief Incoming messages are filtered and dispatched to callbacks.
 *
 * @param  sh
 * @param  transport_msg
 *
 * @return true on success, otherwise false
 *******************************************************************************
 */
bool
_LSHandleReply(LSHandle *sh, _LSTransportMessage *transport_msg)
{
    LS_ASSERT(sh != NULL);
    LS_ASSERT(transport_msg != NULL);

    /* FIXME -- Need to call sh->disconnect_handler(sh, sh->disconnect_handler_data); if the service is disconnected */

    bool ret = true;
    _CallMap   *callmap = sh->callmap;
    _TokenList *tokens = _TokenListNew();

    /* Find tokens that handle this message. */

    _ServerInfo server_info;
    memset(&server_info, 0, sizeof(server_info));

    /* Parse the message and find all tokens. */
    _MessageFindTokens(callmap, transport_msg, &server_info, tokens);

    /* logging */
    LSDebugLogIncoming("", transport_msg);

    /* Dispatch message to callbacks referenced by tokens. */
    if (_TokenListLen(tokens) > 0)
    {
        ret = _handle_reply(sh, tokens, transport_msg, &server_info);
    }

    _TokenListFree(tokens);

    /* serviceName may have been allocated in _MessageFindTokens's call to
     * _parse_name_owner_changed */
    g_free(server_info.serviceName);

    return ret;
}

static char *
_json_get_string(jvalue_ref object, const char *label)
{
    jvalue_ref m = jobject_get(object, j_cstr_to_buffer(label));
    if (jis_valid(m) && jis_string(m)) {
        raw_buffer string_buf = jstring_get_fast(m);
        return g_strndup(string_buf.m_str, string_buf.m_len);
    }
    return NULL;
}

static inline void
_SendFakeReply(LSHandle *sh, LSFilterFunc callback, void *ctx,
                    const char *method, const char *errorText)
{
    LSMessage *reply = _LSMessageNewRef(_LSTransportMessageEmpty(), sh);
    reply->transport_msg->client = sh->transport->hub;
    reply->category = LUNABUS_ERROR_CATEGORY;
    reply->method = method;

    char* escaped = g_strescape(errorText, NULL);
    reply->payload = reply->payloadAllocated =
        g_strdup_printf("{\"returnValue\": false, \"errorCode\": 1, \"errorText\": \"%s\"}", escaped);
    g_free(escaped);

    _LSMessageParsePayload(reply);

    callback(sh, reply, ctx);
    LSMessageUnref(reply);
}

/*
 * TODO: rename this function. It kind of made sense in the dbus-based world,
 * but doesn't really anymore.
 */
static bool
_send_match(LSHandle        *sh,
             LSUri          *luri,
             const char     *payload,
             LSFilterFunc    callback,
             void           *ctx,
             _Call        **ret_call,
             LSError        *lserror)
{
    bool retVal = true;
    char *category = NULL;
    char *method = NULL;
    char *key = NULL;
    _Call *call = NULL;
    LSMessageToken token = LSMESSAGE_TOKEN_INVALID;

    jvalue_ref object = jdom_create(j_cstr_to_buffer(payload), jschema_all(), NULL);
    if (jis_null(object))
    {
        _SendFakeReply(sh, callback, ctx, "addmatch", "Invalid signal/addmatch payload");
        goto done;
    }

    category = _json_get_string(object, "category");
    if (!category)
    {
        _SendFakeReply(sh, callback, ctx, "addmatch",  "The 'category' parameter is missing or is not a string");
        goto done;
    }

    method = _json_get_string(object, "method");

    if (category) {
        retVal = LSTransportRegisterSignal(sh->transport, category, method, sh->is_public_bus, &token, lserror);
        if (!retVal) goto done;
    }

    if (category && method)
    {
        key = g_strdup_printf("%s/%s", category, method);
    }
    else if (category)
    {
        key = g_strdup_printf("%s", category);
    }

    call = _CallNew(sh, CALL_TYPE_SIGNAL, luri->serviceName, callback, ctx, token, method);

    call->signal_category = category;
    call->signal_method = method;
    call->match_key = key;

    /* release ownership over method and category (moved to call structure) */
    category = NULL;
    method = NULL;

    *ret_call = call;

done:
    j_release(&object);

    g_free(category);
    g_free(method);

    return retVal;
}

static bool
_send_reg_server_status(LSHandle *sh,
             LSUri          *luri,
             const char     *payload,
             LSFilterFunc    callback,
             void           *ctx,
             _Call        **ret_call,
             LSError *lserror)
{
    bool retVal = true;
    char *serviceName = NULL;

    jvalue_ref object = jdom_create(j_cstr_to_buffer(payload), jschema_all(), NULL);
    if (jis_null(object))
    {
        _SendFakeReply(sh, callback, ctx, "registerServerStatus", "Malformed json.");
        goto done;
    }

    serviceName = _json_get_string(object, "serviceName");
    if (!serviceName)
    {
        _SendFakeReply(sh, callback, ctx, "registerServerStatus", "Invalid payload.");
        goto done;
    }

    LSMessageToken token;
    retVal = LSTransportSendQueryServiceStatus(sh->transport, serviceName, sh->is_public_bus, &token, lserror);
    if (!retVal)
    {
        _LSErrorSet(lserror, MSGID_LS_SEND_ERROR, -1, "Could not send QueryServiceStatus.");
        goto done;
    }

    retVal = LSTransportRegisterSignalServiceStatus(sh->transport, serviceName, sh->is_public_bus, NULL, lserror);
    if (!retVal)
    {
        _LSErrorSet(lserror, MSGID_LS_SEND_ERROR, -1, "Could not send RegisterSignalServiceStatus.");
        goto done;
    }

    *ret_call = _CallNew(sh, CALL_TYPE_SIGNAL_SERVER_STATUS, serviceName, callback, ctx, token, luri->methodName);

done:
    j_release(&object);

    g_free(serviceName);

    return retVal;
}

static bool
_send_reg_service_category(LSHandle     *sh,
                           LSUri        *luri,
                           const char   *payload,
                           LSFilterFunc callback,
                           void         *ctx,
                           _Call        **ret_call,
                           LSError      *lserror)
{
    /* Register watch for service category changes.
     *
     * For a specific category: {"serviceName": "com.palm.A", "category": "/category1"}
     * For every category: {"serviceName": "com.palm.A"}
     */

    bool retVal = true;
    char *category = NULL;
    char *signal_category = NULL;
    char *service_name = NULL;

    jvalue_ref object = jdom_create(j_cstr_to_buffer(payload), jschema_all(), NULL);
    if (!jis_valid(object))
    {
        _SendFakeReply(sh, callback, ctx, "registerServiceCategory", "Malformed json.");
        goto done;
    }

    service_name = _json_get_string(object, "serviceName");
    if (!service_name)
    {
        _SendFakeReply(sh, callback, ctx, "registerServiceCategory",  "Invalid payload. Missing \"serviceName\".");
        goto done;
    }

    category = _json_get_string(object, "category");
    if (category && *category != '/')
    {
        _SendFakeReply(sh, callback, ctx, "registerServiceCategory",
                       "Invalid payload. \"category\" should begin with /.");
        goto done;
    }

    if (category)
    {
        signal_category = g_strdup_printf(LUNABUS_WATCH_CATEGORY_CATEGORY "/%s%s",
                                          service_name, category);
    }
    else
    {
        signal_category = g_strdup_printf(LUNABUS_WATCH_CATEGORY_CATEGORY "/%s", service_name);
    }

    LSMessageToken token;
    retVal = LSTransportSendQueryServiceCategory(sh->transport,
                                                 sh->is_public_bus,
                                                 service_name, category,
                                                 &token, lserror);
    if (!retVal)
    {
        _LSErrorSet(lserror, MSGID_LS_SEND_ERROR, -1, "Could not send QueryServiceCategory.");
        goto done;
    }

    *ret_call = _CallNew(sh, CALL_TYPE_SIGNAL, service_name, callback, ctx, token, NULL);
    (*ret_call)->match_key = g_strdup(signal_category);
    (*ret_call)->signal_category = signal_category; signal_category = NULL;

done:
    j_release(&object);

    g_free(category);
    g_free(service_name);
    g_free(signal_category);

    return retVal;
}

static bool
_send_hub_method_call(LSHandle     *sh,
                      LSUri        *luri,
                      const char   *payload,
                      LSFilterFunc callback,
                      void         *ctx,
                      _Call        **ret_call,
                      LSError      *lserror)
{
    PMTRACE_CLIENT_PREPARE(sh->name, luri->serviceName, luri->methodName);

    LSMessageToken token;
    if (!LSTransportSendMethodToHub(sh->transport, luri->methodName, payload, &token, lserror))
    {
        _LSErrorSet(lserror, MSGID_LS_SEND_ERROR, -1,
                    "Could not send method %s to %s", luri->methodName, luri->serviceName);
        return false;
    }

    PMTRACE_CLIENT_CALL(sh->name, luri->serviceName, luri->methodName, token);

    LS_ASSERT(ret_call);
    *ret_call = _CallNew(sh, CALL_TYPE_METHOD_CALL,  luri->serviceName, callback, ctx, token, NULL);
    return true;
}

static bool
_send_method_call(LSHandle *sh,
             LSUri      *luri,
             const char *payload,
             const char *applicationID,
             LSFilterFunc    callback,
             void           *ctx,
             _Call         **ret_call,
             LSError *lserror)
{
    PMTRACE_CLIENT_PREPARE(sh->name, luri->serviceName, luri->methodName);

    LSMessageToken token;
    if (!LSTransportSend(sh->transport, luri->serviceName, sh->is_public_bus,
                         luri->objectPath, luri->methodName, payload, applicationID, &token, lserror))
    {
        _LSErrorSet(lserror, MSGID_LS_SEND_ERROR, -1,
                    "Could not send %s/%s", luri->objectPath ? luri->objectPath : "", luri->methodName);
        return false;
    }

    PMTRACE_CLIENT_CALL(sh->name, luri->serviceName, luri->methodName, token);

    if (callback)
    {
        *ret_call = _CallNew(sh, CALL_TYPE_METHOD_CALL, luri->serviceName, callback, ctx, token, luri->methodName);
    }

    return true;
}

static bool
_cancel_method_call(LSHandle *sh, _Call *call, LSError *lserror)
{
    if (DEBUG_TRACING)
    {
        LOG_LS_DEBUG("TX: %s \"%s\" token <<%ld>>", __FUNCTION__, call->serviceName, call->token);
    }

    // luna://com.hhahha.haha/com/palm/luna/private/cancel {"token":17}

    return LSTransportCancelMethodCall(sh->transport, call->serviceName, call->token, sh->is_public_bus, lserror);
}

static bool
_cancel_signal(LSHandle *sh, _Call *call, LSError *lserror)
{
    if (DEBUG_TRACING)
    {
        LOG_LS_DEBUG("TX: %s token <<%ld>>", __FUNCTION__, call->token);
    }

    /* SIGNAL */
    if ((call->signal_category != NULL) || (call->signal_method != NULL))
    {
        if (!LSTransportUnregisterSignal(sh->transport, call->signal_category, call->signal_method,
                                         sh->is_public_bus, NULL, lserror))
        {
            return false;
        }
    }
    return true;
}

static bool
_LSSignalSendCommon(LSHandle *sh, const char *uri, const char *payload,
             bool typecheck, LSError *lserror)
{
    LSHANDLE_VALIDATE(sh);
    LS_ASSERT(uri);

    if (unlikely(_ls_enable_utf8_validation))
    {
        if (!g_utf8_validate(payload, -1, NULL))
        {
            _LSErrorSet(lserror, MSGID_LS_INVALID_PAYLOAD, -EINVAL, "%s: payload is not utf-8",
                        __FUNCTION__);
            return false;
        }
    }

    if (unlikely(!payload || (strcmp(payload, "") == 0)))
    {
        _LSErrorSet(lserror, MSGID_LS_INVALID_PAYLOAD, -EINVAL, "Empty payload is not valid JSON. Use {}");
        return false;
    }

    LSUri *luri = LSUriParse(uri, lserror);
    if (!luri)
    {
        return false;
    }

    if (typecheck)
    {
        /* typecheck the signal, warn if we haven't done a
         * LSRegisterCategory() with the the same signal name.
         */
        LSCategoryTable *table;
        table = (LSCategoryTable*)
            g_hash_table_lookup(sh->tableHandlers, luri->objectPath);
        if (!table || !g_hash_table_lookup(table->signals, luri->methodName))
        {
            LOG_LS_WARNING(MSGID_LS_SIGNAL_NOT_REGISTERED, 1,
                           PMLOGKS("URI", uri),
                           "%s: Warning: you did not register signal %s via "
                           "LSRegisterCategory().", __FUNCTION__, uri);
        }
    }

    bool retVal = LSTransportSendSignal(sh->transport,
                                   luri->objectPath,
                                   luri->methodName,
                                   payload,
                                   sh->is_public_bus,
                                   lserror);

    LSUriFree(luri);

    return retVal;
}

/**
 * @} END OF LunaServiceClientInternals
 * @endcond
 */

/**
 * @addtogroup LunaServiceClient
 * @{
 */

/**
 *******************************************************************************
 * @brief Sends payload to service at the specified uri.
 *
 * @param sh        IN  handle to service
 * @param uri       IN  fully qualified path to service's method
 * @param payload   IN  some string, usually following json object semantics
 * @param callback  IN  function callback to be called when responses arrive
 * @param ctx       IN  user data to be passed to callback
 * @param ret_token OUT token which identifies responses to this call
 * @param lserror   OUT set on error
 *
 * Special signals usage:
 *
 * Register for any ServerStatus signals:
 *
 * LSCall(sh, "luna://com.webos.service.bus/signal/registerServerStatus",
 *            "{"serviceName": "com.palm.telephony"}", callback, ctx, lserror);
 *
 * Register for any signals from (category, method):
 *
 * LSCall(sh, "luna://com.webos.service.bus/signal/addmatch",
 *            "{"category": "/com/palm/bluetooth/gap","
 *            " "method": "radioon"}", callback, ctx, lserror);
 *
 * Register for any signals from category:
 *
 * LSCall(sh, "luna://com.webos.service.bus/signal/addmatch",
 *            "{"category": "/com/palm/bluetooth/gap"}",
 *            callback, ctx, lserror);
 *
 * @return true on success, otherwise false
 *******************************************************************************
 */
bool
LSCall(LSHandle *sh, const char *uri, const char *payload,
       LSFilterFunc callback, void *ctx,
       LSMessageToken *ret_token, LSError *lserror)
{
    return _LSCallFromApplicationCommon(sh, uri, payload, NULL, /*AppID*/
                callback, ctx, ret_token, false, lserror);
}

/**
 *******************************************************************************
 * @brief Sends a message to service like LSCall() except it only
 *        expects one response and does not need to be cancelled
 *        via LSCallCancel().
 *
 * @param sh        IN  handle to service
 * @param uri       IN  fully qualified path to service's method
 * @param payload   IN  some string, usually following json object semantics
 * @param callback  IN  function callback to be called when responses arrive
 * @param ctx       IN  user data to be passed to callback
 * @param ret_token OUT token which identifies responses to this call
 * @param lserror   OUT set on error
 *
 * @return true on success, otherwise false
 *******************************************************************************
 */
bool
LSCallOneReply(LSHandle *sh, const char *uri, const char *payload,
       LSFilterFunc callback, void *ctx,
       LSMessageToken *ret_token, LSError *lserror)
{
#ifndef WEBOS_MASS_PRODUCTION
    jvalue_ref object = jdom_create(j_cstr_to_buffer(payload), jschema_all(), NULL);
    if(jis_object(object))
    {
        jvalue_ref subscribe;
        if (jobject_get_exists(object, j_cstr_to_buffer("subscribe"), &subscribe))
        {
            bool value;
            if (jboolean_get(subscribe, &value) == CONV_OK && value)
            {
                LOG_LS_WARNING(MSGID_LS_INVALID_PAYLOAD, 0, "It is ambiguous to have \"subscribe\" in one reply call."
                                                            "Service %s, uri %s\n", sh->name, uri);
            }
        }
    }
    j_release(&object);
#endif
    return _LSCallFromApplicationCommon(sh, uri, payload, NULL, /*AppID*/
                callback, ctx, ret_token, true, lserror);
}


/**
 *******************************************************************************
 * @brief Special LSCall() that sends an applicationID.
 *
 * See LSCall().
 *
 * @param sh            IN  handle to service
 * @param uri           IN  fully qualified path to service's method
 * @param payload       IN  some string, usually following json object semantics
 * @param applicationID IN  application id
 * @param callback      IN  function callback to be called when responses arrive
 * @param ctx           IN  user data to be passed to callback
 * @param ret_token     OUT token which identifies responses to this call
 * @param lserror       OUT set on error
 *
 * @return true on success, otherwise false
 *******************************************************************************
 */
bool
LSCallFromApplication(LSHandle *sh, const char *uri, const char *payload,
       const char *applicationID,
       LSFilterFunc callback, void *ctx,
       LSMessageToken *ret_token, LSError *lserror)
{
    return _LSCallFromApplicationCommon(sh, uri, payload, applicationID,
                callback, ctx, ret_token, false, lserror);
}

/**
 *******************************************************************************
 * @brief Special LSCallOneReply() that sends an applicationID.
 *
 * See LSCallOneReply().
 *
 * @param sh            IN  handle to service
 * @param uri           IN  fully qualified path to service's method
 * @param payload       IN  some string, usually following json object semantics
 * @param applicationID IN  application id
 * @param callback      IN  function callback to be called when responses arrive
 * @param ctx           IN  user data to be passed to callback
 * @param ret_token     OUT token which identifies responses to this call
 * @param lserror       OUT set on error
 *
 * @return true on success, otherwise false
 *******************************************************************************
 */
bool
LSCallFromApplicationOneReply(
       LSHandle *sh, const char *uri, const char *payload,
       const char *applicationID,
       LSFilterFunc callback, void *ctx,
       LSMessageToken *ret_token, LSError *lserror)
{
    return _LSCallFromApplicationCommon(sh, uri, payload, applicationID,
                callback, ctx, ret_token, true, lserror);
}

static regex_t lunabus_service_name_regex;
static pthread_mutex_t regex_lock = PTHREAD_MUTEX_INITIALIZER;

static void InitLunabusServiceNameRegex()
{
    int res = regcomp(&lunabus_service_name_regex,
                      LUNABUS_SERVICE_NAME_REGEX,
                      REG_EXTENDED|REG_NOSUB);
    LS_ASSERT(res == 0);
}

static const regex_t *
GetLunabusServiceNameRegex(void)
{
    static pthread_once_t initialized = PTHREAD_ONCE_INIT;
    (void) pthread_once(&initialized, InitLunabusServiceNameRegex);

    static uint8_t count_reset_regex = 0;
    if ((count_reset_regex = (count_reset_regex + 1) % 200) == 0) {
        /* Reset regex_t at every 200 executions amortizing its cost
         * Some clients use a semi-random service name causing memory accumulation
         * See bug (will not fix; it's by design):
         *   https://sourceware.org/bugzilla/show_bug.cgi?id=12567
         * Simple sample program demonstrating the issue:
         *   https://sourceware.org/bugzilla/attachment.cgi?id=5291
         */
        regfree(&lunabus_service_name_regex);
        InitLunabusServiceNameRegex();
    }
    return &lunabus_service_name_regex;
}

static bool
_LSCallFromApplicationCommon(LSHandle *sh, const char *uri,
       const char *payload,
       const char *applicationID,
       LSFilterFunc callback, void *ctx,
       LSMessageToken *ret_token, bool single, LSError *lserror)
{
    _LSErrorIfFail(sh != NULL, lserror, MSGID_LS_INVALID_HANDLE);
    _LSErrorIfFail(uri != NULL, lserror, MSGID_LS_INVALID_URI);
    _LSErrorIfFail(payload != NULL, lserror, MSGID_LS_INVALID_PAYLOAD);

    if (applicationID && !_LSTransportGetPrivileged(sh->transport))
    {
        _LSErrorSet(lserror, MSGID_LS_PRIVILEDGES_ERROR, LS_ERROR_CODE_NOT_PRIVILEGED, LS_ERROR_TEXT_NOT_PRIVILEGED, applicationID);
        return false;
    }

    LSHANDLE_VALIDATE(sh);

    if (unlikely(_ls_enable_utf8_validation))
    {
        if (!g_utf8_validate (payload, -1, NULL))
        {
            _LSErrorSet(lserror, MSGID_LS_INVALID_PAYLOAD, -EINVAL, "%s: payload is not utf-8",
                        __FUNCTION__);
            return false;
        }
    }

    if (unlikely(!payload || (strcmp(payload, "") == 0)))
    {
        _LSErrorSet(lserror, MSGID_LS_INVALID_PAYLOAD, -EINVAL, "Empty payload is not valid JSON. Use {}");
        return false;
    }

    LSUri * luri = LSUriParse(uri, lserror);
    if (!luri)
    {
        return false;
    }
    LS_ASSERT(pthread_mutex_lock(&regex_lock) == 0);
    int failure = regexec(GetLunabusServiceNameRegex(), luri->serviceName, 0, NULL, 0);
    LS_ASSERT(pthread_mutex_unlock(&regex_lock) == 0);

    bool retVal = false;
    _Call *call = NULL;

    _CallMapLock(sh->callmap);
    if (!failure)
    {
        if (callback)
        {
            if (strcmp(luri->objectPath, "/signal") == 0)
            {
                // uri == "luna://com.webos.service.bus/signal/addmatch"
                if (strcmp(luri->methodName, "addmatch") == 0)
                {
                    retVal = _send_match(sh, luri, payload, callback, ctx, &call, lserror);
                }
                // uri == "luna://com.webos.service.bus/signal/registerServerStatus"
                else if (strcmp(luri->methodName, "registerServerStatus") == 0)
                {
                    retVal = _send_reg_server_status(sh, luri, payload, callback, ctx, &call, lserror);
                }
                // uri == "luna://com.webos.service.bus/signal/registerServiceCategory"
                else if (strcmp(luri->methodName, "registerServiceCategory") == 0)
                {
                    retVal = _send_reg_service_category(sh, luri, payload, callback, ctx, &call, lserror);
                }
                else
                {
                    char *error = g_strdup_printf("Invalid method \"%s\" to lunabus LSCall.", luri->methodName);
                    _SendFakeReply(sh, callback, ctx, NULL, error);
                    g_free(error);
                }
            }
            else
            {
                retVal = _send_hub_method_call(sh, luri, payload, callback, ctx, &call, lserror);
            }
        }
        else
        {
            _LSErrorSet(lserror, MSGID_LS_NO_CALLBACK, -EINVAL,
                "Invalid parameters to lunabus LSCall. No callback specified.");
        }
    }
    else
    {
         retVal = _send_method_call(sh, luri, payload, applicationID, callback, ctx, &call, lserror);
    }

    if (ret_token)
    {
        *ret_token = call ? call->token : LSMESSAGE_TOKEN_INVALID;
    }

    if (retVal)
    {
        if (call)
        {
            (void)_CallInsert(sh->callmap, call, single, lserror);
        }

        if (DEBUG_TRACING) _CallDebug(call, uri, payload);
    }

    _CallMapUnlock(sh->callmap);
    LSUriFree(luri);
    return retVal;
}

static
void _send_timeout_msg(_Call * call)
{
    LS_ASSERT(call != NULL);
    LSHANDLE_VALIDATE(call->sh);

    if (call->type == CALL_TYPE_METHOD_CALL && call->callback)
    {
        LSMessage *reply = _LSMessageNewRef(_LSTransportMessageEmpty(), call->sh);

        reply->responseToken = call->token;

        reply->category = LUNABUS_ERROR_CATEGORY;
        reply->method = LUNABUS_ERROR_CALL_TIMEOUT;

        reply->payloadAllocated = g_strdup_printf(
            "{"
            "\"returnValue\":false,"
            "\"errorCode\":-1,"
            "\"errorText\":\"Timeout expired for call.\"}");

        reply->payload = reply->payloadAllocated;

        _LSMessageParsePayload(reply);
        (void)call->callback(call->sh, reply, call->ctx);

        LSMessageUnref(reply);
    }
}

static gboolean
OnCallTimedOut(_Call *call)
{
    LSError lserror;
    LSErrorInit(&lserror);

    if (!LSCallCancel(call->sh, call->token, &lserror))
    {
        LSErrorFree(&lserror);
    }
    call->timer_source = NULL;

    // Send fake message to sender if call timed out
    _send_timeout_msg(call);

    return FALSE;  /* One-shot timer */
}

static void
ResetCallTimeout(_Call *call)
{
    if (call->timer_source != NULL)
    {
        g_source_destroy(call->timer_source);
        g_source_unref(call->timer_source);
    }

    if (call->timeout_ms > 0)
    {
        _CallAddReference(call);
        call->timer_source = g_timeout_source_new(call->timeout_ms);
        g_source_set_callback(call->timer_source, (GSourceFunc) OnCallTimedOut, call, (GDestroyNotify) _CallRelease);
        (void)g_source_attach(call->timer_source, call->sh->context);
    }
    else
    {
        call->timer_source = NULL;
    }
}

/**
 *******************************************************************************
 * @brief Sets timeout for a method call. The call will be canceled if no reply
 *        is received after the timeout_ms milliseconds.
 *
 * @param sh         IN  handle to service
 * @param token      IN  message token
 * @param timeout_ms IN  timeout in ms
 * @param lserror    OUT set on error
 *
 * @return true on success, otherwise false
 *******************************************************************************
 */
bool
LSCallSetTimeout(LSHandle *sh, LSMessageToken token, int timeout_ms, LSError *lserror)
{
    _LSErrorIfFail(sh != NULL, lserror, MSGID_LS_INVALID_HANDLE);

    if (DEBUG_TRACING)
    {
        g_debug("TX: %s token <<%ld>>", __FUNCTION__, token);
    }

    LSHANDLE_VALIDATE(sh);

    _CallMap *callmap = sh->callmap;

    _Call *call = _CallAcquire(callmap, token);
    if (!call)
    {
        _LSErrorSetNoPrint(lserror, -1, "Could not find call %ld to set timeout.", token);
        return false;
    }

    if (call->type != CALL_TYPE_METHOD_CALL)
    {
        _CallRelease(call);
        _LSErrorSetNoPrint(lserror, -1, "Call %ld isn't a method call.", token);
        return false;
    }
    call->timeout_ms = timeout_ms;

    ResetCallTimeout(call);

    _CallRelease(call);
    return true;
}


/**
 *******************************************************************************
 * @brief Sends a cancel message to service to end call session and also
 *        unregisters any callback associated with call.
 *
 * @param sh      IN  handle to service
 * @param token   IN  message token
 * @param lserror OUT set on error
 *
 * @return true on success, otherwise false
 *******************************************************************************
 */
bool
LSCallCancel(LSHandle *sh, LSMessageToken token, LSError *lserror)
{
    _LSErrorIfFail(sh != NULL, lserror, MSGID_LS_INVALID_HANDLE);

    if (DEBUG_TRACING)
    {
        LOG_LS_DEBUG("TX: %s token <<%ld>>", __FUNCTION__, token);
    }

    LSHANDLE_VALIDATE(sh);

    bool retVal = false;
    _CallMap *callmap = sh->callmap;

    _Call * call = _CallAcquireEx(callmap, token, false); // +1
    if (!call)
    {
        _LSErrorSetNoPrint(lserror, -1, "Could not find call %ld to cancel.", token);
        return false;
    }

    switch (call->type)
    {
        case CALL_TYPE_METHOD_CALL:
        {
            LS_ASSERT(pthread_mutex_lock(&regex_lock) == 0);
            int failure = regexec(GetLunabusServiceNameRegex(), call->serviceName, 0, NULL, 0);
            LS_ASSERT(pthread_mutex_unlock(&regex_lock) == 0);
            if (!failure)
            {
                // No need to inform ls-hubd about cancellation of com.webos.service.bus methods
                retVal = true;
            }
            else
            {
                retVal = _cancel_method_call(sh, call, lserror);
            }
            break;
        }
        case CALL_TYPE_SIGNAL:
        {
            retVal = _cancel_signal(sh, call, lserror);
            break;
        }
        case CALL_TYPE_SIGNAL_SERVER_STATUS:
        {
            /* Multiple registrations for the same service are ref-counted on the hub
            * side, so if "registerServerStatus" is called on the same service
            * twice, this will need to be called twice before the watch is truly destroyed */
            retVal = _service_watch_disable(sh, call);
            break;
        }
    }

    _CallRemove(callmap, call);

    _CallLock(call);
    _CallRelease(call); // -1

    return retVal;
}

static bool
_ServerStatusHelper(LSHandle *sh, LSMessage *message, void *ctx)
{
    JSchemaInfo schemaInfo;
    jschema_info_init(&schemaInfo, jschema_all(), NULL, NULL);

    const char *payload = LSMessageGetPayload(message);

    jvalue_ref object = jdom_parse(j_cstr_to_buffer(payload), DOMOPT_NOOPT,
                                   &schemaInfo);

    _ServerStatus *server_status = (_ServerStatus*)ctx;
    if (!server_status) goto error;

    if (!jis_null(object))
    {
        bool connected;

        jvalue_ref serviceObj = NULL;
        jvalue_ref connectedObj = NULL;

        if (!jobject_get_exists(object, J_CSTR_TO_BUF("serviceName"),
                                &serviceObj)) goto error;
        if (!jobject_get_exists(object, J_CSTR_TO_BUF("connected"),
                                &connectedObj)) goto error;

        (void)jboolean_get(connectedObj, &connected);/* TODO: handle appropriately */

        if (server_status->callback)
        {
            LOCAL_CSTR_FROM_BUF(serviceName, jstring_get_fast(serviceObj));
            server_status->callback
                (sh, serviceName, connected, server_status->ctx);
        }
    }

error:
    j_release(&object);
    return true;
}

/**
 *******************************************************************************
 * @brief Register a callback to be called when the server goes up or
 *        comes down.  Callback may be called in this context if
 *        the server is already up.
 *
 * Performs LSCall(sh, "luna://com.webos.service.bus/signal/registerServerStatus").
 *
 * @param sh          IN  handle to service
 * @param serviceName IN  service name to monitor for connect/disconnect.
 * @param func        IN  function callback
 * @param ctx         IN  user data to be passed to callback
 * @param cookie      OUT token to use for to unregister the callback
 * @param lserror     OUT set on error
 *
 * @return true on success, otherwise false
 *******************************************************************************
 */

bool LSRegisterServerStatusEx(LSHandle *sh, const char *serviceName,
                              LSServerStatusFunc func, void *ctx,
                              void **cookie, LSError *lserror)
{
    char    *payload;

    LSHANDLE_VALIDATE(sh);

    payload = g_strdup_printf("{\"serviceName\":\"%s\"}", serviceName);

    _ServerStatus *server_status;
    server_status = g_new0(_ServerStatus, 1);

    server_status->callback = func;
    server_status->ctx = ctx;
    server_status->token = LSMESSAGE_TOKEN_INVALID;

    if (!LSCall(sh,
                "luna://com.webos.service.bus/signal/registerServerStatus",
                payload, _ServerStatusHelper, server_status,
                &server_status->token, lserror))
    {
        g_free(payload);
        g_free(server_status);
        return false;
    }

    if (cookie)
        *cookie = server_status;

    g_free(payload);
    return true;
}

/**
 *******************************************************************************
 * @brief Cancel receiving notifications about server status.
 *
 * If unlikely false is returned, the subscription hasn't been canceled,
 * and the associated memory hasn't been freed yet. This can happen if
 * the system suffers from low memory.
 *
 * The call can be repeated until true is returned. Once that happened,
 * the value of cookie is invalid, and should not be used.
 *
 * @param sh      IN  handle to service
 * @param cookie  IN  token obtained during registration, can't be NULL
 * @param lserror OUT set on error
 *
 * @return true on success, otherwise false
 *
 * @sa LSRegisterServerStatusEx
 *******************************************************************************
 */
bool LSCancelServerStatus(LSHandle *sh, void *cookie, LSError *lserror)
{
    LSHANDLE_VALIDATE(sh);
    LS_ASSERT(cookie != NULL && "A valid cookie from LSRegisterServerStatus() should be passed");

    _ServerStatus *server_status = (_ServerStatus *) cookie;

    if (!LSCallCancel(sh, server_status->token, lserror))
    {
        return false;
    }

    g_free(server_status);
    return true;
}

/** @} END OF LunaServiceClient */

/**
 * @addtogroup LunaServiceSignals
 *
 * @{
 */

/**
 *******************************************************************************
 * @brief Attach a callback to be called when signal is received.
 *
 * @param sh            IN  handle to service
 * @param category      IN  category name to monitor
 * @param method        IN  method name to monitor
 * @param filterFunc    IN  callback to filter function
 * @param ctx           IN  user data to be passed to callback
 * @param responseToken OUT response token
 * @param lserror       OUT set on error
 *
 * @deprecated Use LSCall() with uri "luna://com.webos.service.bus/signal/addmatch",
 *             and payload "{"category": "/category/name", "method":"methodName"}",
 *
 * @return true on success, otherwise false
 *******************************************************************************
 */
bool
LSSignalCall(LSHandle *sh,
         const char *category, const char *method,
         LSFilterFunc filterFunc, void *ctx,
         LSMessageToken *responseToken,
         LSError *lserror)
{
    bool retVal;
    char *payload;

    LSHANDLE_VALIDATE(sh);

    if (category && method)
    {
        payload  = g_strdup_printf(
            "{\"category\":\"%s\",\"method\":\"%s\"}", category, method);
    }
    else if (category)
    {
        payload  = g_strdup_printf("{\"category\":\"%s\"}", category);
    }
    else
    {
        _LSErrorSet(lserror, MSGID_LS_INVALID_CALL, -EINVAL, "Invalid arguments to %s", __FUNCTION__);
        return false;
    }

    retVal = LSCall(sh, "luna://com.webos.service.bus/signal/addmatch", payload,
                    filterFunc, ctx, responseToken, lserror);

    g_free(payload);

    return retVal;
}

/**
 *******************************************************************************
 * @brief Remove callback & match for specific signal.
 *
 * @param sh      IN  handle to service
 * @param token   IN  message token
 * @param lserror OUT set on error
 *
 * @deprecated Use LSCallCancel() instead.
 *
 * @return true on success, otherwise false
 *******************************************************************************
 */
bool
LSSignalCallCancel(LSHandle *sh, LSMessageToken token, LSError *lserror)
{
    return LSCallCancel(sh, token, lserror);
}

/**
 *******************************************************************************
 * @brief Variant of LSSignalSend() that does not attempt to check if the
 *        signal is registered via LSRegisterCategory() this should only
 *        be used if you don't use LSRegisterCategory()
 *        (i.e. JNI implementation)
 *
 * @param sh      IN  handle to service
 * @param uri     IN  fully qualified path to service's method
 * @param payload IN  some string, usually following json object semantics
 * @param lserror OUT set on error
 *
 * @return true on success, otherwise false
 *******************************************************************************
 */
bool
LSSignalSendNoTypecheck(LSHandle *sh, const char *uri, const char *payload,
             LSError *lserror)
{
    return _LSSignalSendCommon(sh, uri, payload, false, lserror);
}

/**
 *******************************************************************************
 * @brief Send a signal.
 *
 * @param  sh      IN  handle to service
 * @param  uri     IN  fully qualified path to service's method
 * @param  payload IN  some string, usually following json object semantics
 * @param  lserror OUT set on error
 *
 * @return true on success, otherwise false
 *******************************************************************************
 */
bool
LSSignalSend(LSHandle *sh, const char *uri, const char *payload,
             LSError *lserror)
{
    return _LSSignalSendCommon(sh, uri, payload, true, lserror);
}

/** @} END OF LunaServiceSignals */
