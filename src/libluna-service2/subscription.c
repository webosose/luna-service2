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
#include <errno.h>
#include <string.h>
#include <pthread.h>

#include <luna-service2/lunaservice.h>
#include "message.h"
#include "base.h"
#include "subscription.h"

/**
 * @cond INTERNAL
 * @addtogroup LunaServiceInternals
 * @{
 */

/**
 *******************************************************************************
 * @brief Internal representation of a subscription list.
 *******************************************************************************
 */
typedef GPtrArray _SubList;

/**
 *******************************************************************************
 * @brief Internal representation of a subscriber cancel notification callback
 *        list.
 *******************************************************************************
 */
typedef GPtrArray _CancelNotifyCallbackList;

/**
 *******************************************************************************
 * @brief One subscription.
 *******************************************************************************
 */
typedef struct _Subscription
{
    LSMessage       *message;
    GPtrArray       *keys;

    int              ref;

} _Subscription;

/**
 *******************************************************************************
 * @brief Internal struct that contains all the subscriptions.
 *******************************************************************************
 */
struct _Catalog {

    pthread_mutex_t  lock;

    LSHandle  *sh;

    // each key is user defined
    // each token is ':sender.connection.serial'

    GHashTable *token_map;           //< map of token -> _Subscription
    GHashTable *subscription_lists;  //< map from key ->
                                     //   list of tokens (_SubList)
    GHashTable *client_subscriptions;//< map unique_name ->
                                     //   list of tokens (_SubList)

    LSFilterFunc cancel_function;
    void*        cancel_function_ctx;

    _CancelNotifyCallbackList *cancel_notify_list;
};

/**
 *******************************************************************************
 * @brief Subscriber's cancellation notification callback.
 *******************************************************************************
 */
typedef struct _SubscriberCancelNotification
{
    LSCancelNotificationFunc function;
    void                    *context;
} _SubscriberCancelNotification;

/**
 *******************************************************************************
 * @brief User reference to a subscription list.
 *******************************************************************************
 */
struct LSSubscriptionIter {

    _SubList *tokens;          //< copy of the subscription list
    _Catalog *catalog;

    GSList   *seen_messages;   //< ref-counted references to messages iterated
    int index;
};

static void _SubscriptionRelease(_Catalog *catalog, _Subscription *subs);

static void
_CatalogLock(_Catalog *catalog)
{
    pthread_mutex_lock(&catalog->lock);
}

static void
_CatalogUnlock(_Catalog *catalog)
{
    pthread_mutex_unlock(&catalog->lock);
}

static void
_SubscriptionRemove(_Catalog *catalog, _Subscription *subs, const char *token)
{
    _CatalogLock(catalog);
    g_hash_table_remove(catalog->token_map, token);
    _CatalogUnlock(catalog);

    _SubscriptionRelease(catalog, subs);
}

static void
_SubscriptionFree(_Catalog *catalog, _Subscription *subs)
{
    if (subs)
    {
        LSMessageUnref(subs->message);

        if (subs->keys)
        {
            g_ptr_array_foreach(subs->keys, (GFunc)g_free, NULL);
            g_ptr_array_free(subs->keys, TRUE);
        }

#ifdef MEMCHECK
        memset(subs, 0xFF, sizeof(_Subscription));
#endif

        g_free(subs);
    }
}

static _Subscription *
_SubscriptionAcquire(_Catalog *catalog, const char *uniqueToken)
{
    _CatalogLock(catalog);

    _Subscription *subs=
        g_hash_table_lookup(catalog->token_map, uniqueToken);
    if (subs)
    {
        LS_ASSERT(g_atomic_int_get(&subs->ref) > 0);
        g_atomic_int_inc(&subs->ref);
    }

    _CatalogUnlock(catalog);

    return subs;
}

static void
_SubscriptionRelease(_Catalog *catalog, _Subscription *subs)
{
    if (subs)
    {
        LS_ASSERT(g_atomic_int_get(&subs->ref) > 0);

        if (g_atomic_int_dec_and_test(&subs->ref))
        {
            _SubscriptionFree(catalog, subs);
        }
    }
}

/**
 *******************************************************************************
 * @brief Create a new subscription.
 *
 * @param sh
 * @param message
 *
 * @retval _Subscription, created subscription
 *******************************************************************************
 */
static _Subscription *
_SubscriptionNew(LSHandle *sh, LSMessage *message)
{
    _Subscription *subs;

    subs = g_new0(_Subscription,1);

    subs->ref = 1;
    subs->keys = g_ptr_array_new();

    LSMessageRef(message);
    subs->message = message;

    return subs;
}

/**
 *******************************************************************************
 * @brief Create new subscription List
 *
 * @retval _SubList, created list
 *******************************************************************************
 */
static _SubList *
_SubListNew()
{
    return g_ptr_array_new();
}

static void
_SubListFree(_SubList *tokens)
{
    if (!tokens) return;

    g_ptr_array_foreach(tokens, (GFunc)g_free, NULL);
    g_ptr_array_free(tokens, TRUE);
}

static int
_SubListLen(_SubList *tokens)
{
    if (!tokens) return 0;
    return tokens->len;
}

/**
 *******************************************************************************
 * @brief Add _SubList.
 *
 * @param  tokens
 * @param  data
 *******************************************************************************
 */
static void
_SubListAdd(_SubList *tokens, char *data)
{
    if (tokens && data)
        g_ptr_array_add(tokens, data);
}

static _SubList*
_SubListDup(_SubList *src)
{
    _SubList *dst = NULL;

    if (src)
    {
        dst = _SubListNew();

        int i;
        for (i = 0; i < src->len; i++)
        {
            char *tok = g_ptr_array_index(src, i);
            g_ptr_array_add(dst, g_strdup(tok));
        }
    }

    return dst;
}

/**
 *******************************************************************************
 * @brief Remove from _SubList.  This is more expensive.
 *
 * @param  tokens
 * @param  data
 *******************************************************************************
 */
static void
_SubListRemove(_SubList *tokens, const char *data)
{
    if (!tokens) return;

    int i;
    for (i = 0; i < tokens->len; i++)
    {
        char *tok = g_ptr_array_index(tokens, i);
        if (strcmp(tok, data) == 0)
        {
            g_ptr_array_remove_index(tokens, i);
            g_free(tok);
            break;
        }
    }
}

static bool
g_char_ptr_array_contains(GPtrArray *array, const char *data)
{
    if (!array) return false;

    int i;
    for (i = 0; i < array->len; i++)
    {
        char *tok = g_ptr_array_index(array, i);
        if (strcmp(tok, data) == 0)
        {
            return true;
        }
    }
    return false;
}

static bool
_SubListContains(_SubList *tokens, const char *data)
{
    if (!tokens) return false;

    int i;
    for (i = 0; i < tokens->len; i++)
    {
        char *tok = g_ptr_array_index(tokens, i);
        if (strcmp(tok, data) == 0)
        {
            return true;
        }
    }
    return false;
}

const char *
_SubListGet(_SubList *tokens, int i)
{
    if (i < 0 || i >= tokens->len)
    {
        LOG_LS_ERROR(MSGID_LS_SUBSCRIPTION_ERR, 0,
                     "%s: attempting to get out of range subscription %d\n"
                     "It is possible you forgot to follow the pattern: "
                     " LSSubscriptionHasNext() + LSSubscriptionNext()",
                     __FUNCTION__, i);
        return NULL;
    }

    LS_ASSERT(i >= 0 && i < tokens->len);
    return g_ptr_array_index(tokens, i);
}

/**
 *******************************************************************************
 * @brief Create a new subscriber cancel notification item.
 *
 * @param  function
 * @param  context
 *
 * @retval _SubscriberCancelNotification, created item
 *******************************************************************************
 */
static _SubscriberCancelNotification *
_SubscriberCancelNotificationNew(LSCancelNotificationFunc function, void *context)
{
    _SubscriberCancelNotification *scn = g_new0(_SubscriberCancelNotification, 1);
    scn->function = function;
    scn->context = context;
    return scn;
}

static void
_SubscriberCancelNotificationFree(_SubscriberCancelNotification *scn)
{
    g_free(scn);
}

/**
 *******************************************************************************
 * @brief Create a new subscriber cancellation notifications list
 *
 * @retval _CancelNotifyCallbackList, created list
 *******************************************************************************
 */
static _CancelNotifyCallbackList *
_SubscriberCancelNotificationListNew()
{
    return g_ptr_array_new_full(1, (GDestroyNotify)_SubscriberCancelNotificationFree);
}

static void
_SubscriberCancelNotificationListFree(_CancelNotifyCallbackList *scnList)
{
    if (!scnList) return;

    g_ptr_array_free(scnList, TRUE);
}

_Catalog *
_CatalogNew(LSHandle *sh)
{
    _Catalog *catalog = g_new0(_Catalog, 1);

    if (pthread_mutex_init(&catalog->lock, NULL))
    {
        LOG_LS_ERROR(MSGID_LS_MUTEX_ERR, 0, "Could not initialize mutex.");
        goto error;
    }

    catalog->token_map = g_hash_table_new_full(
            g_str_hash, g_str_equal, g_free, NULL);

    catalog->subscription_lists = g_hash_table_new_full(
            g_str_hash, g_str_equal, g_free, (GDestroyNotify)_SubListFree);
    catalog->client_subscriptions = g_hash_table_new_full(
            g_str_hash, g_str_equal, g_free, (GDestroyNotify)_SubListFree);

    catalog->sh = sh;

    return catalog;

error:
    _CatalogFree(catalog);
    return NULL;
}

gboolean _TokenMapFree(gpointer key, gpointer value, gpointer user_data)
{
    _Subscription *subs = (_Subscription *) value;
    _Catalog *catalog = (_Catalog *) user_data;
    _SubscriptionRelease(catalog, subs);
    return true;
}

void
_CatalogFree(_Catalog *catalog)
{
    if (catalog)
    {
        if (catalog->token_map)
        {
            g_hash_table_foreach_remove(catalog->token_map, _TokenMapFree, catalog);
            g_hash_table_destroy(catalog->token_map);
        }
        if (catalog->subscription_lists)
        {
            g_hash_table_destroy(catalog->subscription_lists);
        }
        if (catalog->client_subscriptions)
        {
            g_hash_table_destroy(catalog->client_subscriptions);
        }
        if (catalog->cancel_notify_list)
        {
            _SubscriberCancelNotificationListFree(catalog->cancel_notify_list);
        }

#ifdef MEMCHECK
        memset(catalog, 0xFF, sizeof(_Catalog));
#endif

        g_free(catalog);
    }
}

static bool
_CatalogAdd(_Catalog *catalog, const char *key,
              LSMessage *message, LSError *lserror)
{
    if (!LSMessageIsConnected(message))
    {
        _LSErrorSet(lserror, MSGID_LS_SUBSCRIPTION_ERR, -1, "The client has been disconnected");
        return false;
    }

    bool retVal = false;
    const char *token = LSMessageGetUniqueToken(message);
    if (!token)
    {
        _LSErrorSet(lserror, MSGID_LS_TOKEN_ERR, -1, "Could not get unique token");
        return false;
    }

    _CatalogLock(catalog);

    _SubList *list =
        g_hash_table_lookup(catalog->subscription_lists, key);
    if (!list)
    {
        list = _SubListNew();
        g_hash_table_replace(catalog->subscription_lists,
                             g_strdup(key), list);
    }

    _SubList *client_list = NULL;
    _Subscription *subs = NULL;

    const char* client_name = LSMessageGetSender(message);
    if (!client_name)
    {
        _LSErrorSet(lserror, MSGID_LS_UNAME_ERR, -1, "Could not get service unique name");
        goto cleanup;
    }

    client_list =
        g_hash_table_lookup(catalog->client_subscriptions, client_name);
    if (!client_list)
    {
        client_list = _SubListNew();
        g_hash_table_replace(catalog->client_subscriptions,
                             g_strdup(client_name), client_list);
    }

    subs = g_hash_table_lookup(catalog->token_map, token);
    if (!subs)
    {
        subs = _SubscriptionNew(catalog->sh, message);
        if (subs)
        {
            g_hash_table_replace(catalog->token_map, g_strdup(token), subs);
        }
        else
        {
            goto cleanup;
        }
    }
    LS_ASSERT(subs->message == message);

    if (!_SubListContains(list, token))
    {
        _SubListAdd(list, g_strdup(token));
    }

    if (!_SubListContains(client_list, token))
    {
        _SubListAdd(client_list, g_strdup(token));
    }

    if (!g_char_ptr_array_contains(subs->keys, key))
    {
        g_ptr_array_add(subs->keys, g_strdup(key));
    }

    retVal = true;

cleanup:
    _CatalogUnlock(catalog);
    return retVal;
}

static bool
_CatalogRemoveToken(_Catalog *catalog, const char *token,
                             bool notify)
{
    _Subscription *subs = _SubscriptionAcquire(catalog, token);
    if (!subs) return false;

    if (notify && catalog->cancel_function)
    {
        catalog->cancel_function(catalog->sh,
                subs->message, catalog->cancel_function_ctx);
    }

    _CatalogLock(catalog);
    int i;
    // Remove subscription from key sublists
    for (i = 0; i < subs->keys->len; i++)
    {
        const char *key = g_ptr_array_index(subs->keys, i);

        _SubList *sub_list =
            g_hash_table_lookup(catalog->subscription_lists, key);

        _SubListRemove(sub_list, token);

        if (_SubListLen(sub_list) == 0)
        {
            g_hash_table_remove(catalog->subscription_lists, key);
        }
    }

    // Remove subscrition from client subscription list
    const char *client_name = LSMessageGetSender(subs->message);
    _SubList *client_sub_list =
        g_hash_table_lookup(catalog->client_subscriptions, client_name);

    _SubListRemove(client_sub_list, token);

    if (_SubListLen(client_sub_list) == 0)
    {
        g_hash_table_remove(catalog->client_subscriptions, client_name);
    }

    _CatalogUnlock(catalog);

    _SubscriptionRemove(catalog, subs, token);

    _SubscriptionRelease(catalog, subs);

    return true;
}

static void
_CatalogCallCancelNotifications(_Catalog *catalog, const char *uniqueToken)
{
    LS_ASSERT(uniqueToken);
    _CatalogLock(catalog);
    if (catalog->cancel_notify_list)
    {
        int idx;
        for (idx = 0; idx < catalog->cancel_notify_list->len; ++idx)
        {
            _SubscriberCancelNotification *scn = g_ptr_array_index(catalog->cancel_notify_list, idx);
            if (scn->function)
            {
                scn->function(catalog->sh, uniqueToken, scn->context);
            }
        }
    }
    _CatalogUnlock(catalog);
}

bool
_CatalogHandleCancel(_Catalog *catalog, LSMessage *cancelMsg,
                     LSError *lserror)
{
    JSchemaInfo schemaInfo;
    jschema_info_init(&schemaInfo, jschema_all(), NULL, NULL);

    const char *sender;
    int token;
    jvalue_ref tokenObj = NULL;

    const char *payload = LSMessageGetPayload(cancelMsg);

    jvalue_ref object = jdom_parse(j_cstr_to_buffer(payload), DOMOPT_NOOPT,
                                   &schemaInfo);
    if (jis_null(object))
    {
        _LSErrorSet(lserror, MSGID_LS_INVALID_JSON, -EINVAL, "Invalid json");
        goto error;
    }

    sender = LSMessageGetSender(cancelMsg);

    if (!jobject_get_exists(object, J_CSTR_TO_BUF("token"), &tokenObj) ||
        tokenObj == NULL || !jis_number(tokenObj))
    {
        _LSErrorSet(lserror, MSGID_LS_INVALID_JSON, -EINVAL, "Invalid json");
        goto error;
    }

    (void)jnumber_get_i32(tokenObj, &token);/* TODO: handle appropriately */

    char *uniqueToken = g_strdup_printf("%s.%d", sender, token);

    _CatalogCallCancelNotifications(catalog, uniqueToken);
    _CatalogRemoveToken(catalog, uniqueToken, true);

    g_free(uniqueToken);
    j_release(&object);
    return true;

error:
    j_release(&object);
    return false;
}

static _SubList*
_CatalogGetSubList_unlocked(_Catalog *catalog, const char *key)
{
    _SubList *tokens =
        g_hash_table_lookup(catalog->subscription_lists, key);

    return tokens;
}

static bool
_CatalogAddCancelNotification(_Catalog *catalog,
              LSCancelNotificationFunc function, void *context, LSError *lserror)
{
    _CatalogLock(catalog);

    if (!catalog->cancel_notify_list)
    {
        catalog->cancel_notify_list = _SubscriberCancelNotificationListNew();
    }
    g_ptr_array_add(catalog->cancel_notify_list, _SubscriberCancelNotificationNew(function, context));

    _CatalogUnlock(catalog);
    return true;
}

static bool
_CatalogRemoveCancelNotification(_Catalog *catalog,
              LSCancelNotificationFunc function, void *context, LSError *lserror)
{
    bool retVal = false;
    _CatalogLock(catalog);

    if (!catalog->cancel_notify_list)
    {
        _LSErrorSet(lserror, MSGID_LS_CATALOG_ERR, -1, "Cancel notification list not available");
        goto cleanup;
    }

    int idx;
    for (idx = 0; idx < catalog->cancel_notify_list->len; ++idx)
    {
        _SubscriberCancelNotification *scn = g_ptr_array_index(catalog->cancel_notify_list, idx);
        if (scn->function == function && scn->context == context)
        {
            g_ptr_array_remove_index(catalog->cancel_notify_list, idx);
            break;
        }
    }
    retVal = true;

cleanup:
    _CatalogUnlock(catalog);
    return retVal;
}

void _LSCatalogRemoveClientSubscriptions(_Catalog *catalog, _LSTransportClient *client)
{
    LS_ASSERT(catalog != NULL);
    LS_ASSERT(_LSTransportClientGetUniqueName(client) != NULL);

    const char *client_name = _LSTransportClientGetUniqueName(client);

    _CatalogLock(catalog);

    char *key = NULL;
    _SubList *tokens = NULL;
    if (!g_hash_table_lookup_extended(catalog->client_subscriptions, client_name,
                                      (gpointer *) &key, (gpointer *) &tokens))
    {
        LOG_LS_DEBUG("Disconnected service had no subscriptions: %s", client->service_name);
        _CatalogUnlock(catalog);
        return;
    }

    g_hash_table_steal(catalog->client_subscriptions, client_name);
    g_free(key);

    _CatalogUnlock(catalog);

    int i;
    for (i = _SubListLen(tokens) - 1; i >= 0; --i)
    {
        const char *token = _SubListGet(tokens, i);

        _Subscription *subs = _SubscriptionAcquire(catalog, token);
        if (subs)
        {
            _CatalogRemoveToken(catalog, token, true);
            _SubscriptionRelease(catalog, subs);
        }
    }

    _SubListFree(tokens);
}

bool
_LSSubscriptionGetJson(LSHandle *sh, jvalue_ref *ret_obj, LSError *lserror)
{
    _Catalog *catalog = sh->catalog;
    const char *key = NULL;
    _SubList *sub_list = NULL;
    GHashTableIter iter;

    jvalue_ref true_obj = NULL;
    jvalue_ref array = NULL;
    jvalue_ref cur_obj = NULL;
    jvalue_ref sub_array = NULL;
    jvalue_ref key_name = NULL;
    jvalue_ref message_obj = NULL;
    jvalue_ref sub_array_item = NULL;
    jvalue_ref unique_name_obj = NULL;
    jvalue_ref service_name_obj = NULL;

    *ret_obj = jobject_create();
    if (*ret_obj == NULL) goto error;

    true_obj = jboolean_create(true);
    if (true_obj == NULL) goto error;

    array = jarray_create(NULL);
    if (array == NULL) goto error;

    /* returnValue: true,
     * subscriptions: [
     *  { key: key_name, subscribers: [{unique_name: , service_name: }, ...] },
     *  ...
     * ]
     */
    _CatalogLock(catalog);

    g_hash_table_iter_init(&iter, catalog->subscription_lists);

    while (g_hash_table_iter_next(&iter, (gpointer)&key, (gpointer)&sub_list))
    {
        cur_obj = jobject_create();
        if (cur_obj == NULL) goto error;

        sub_array = jarray_create(NULL);
        if (sub_array == NULL) goto error;

        key_name = jstring_create_copy(j_cstr_to_buffer(key));
        if (key_name == NULL) goto error;

        /* iterate over SubList */
        int i = 0;
        const char *token = NULL;
        const int len = _SubListLen(sub_list);
        for (i = 0; i < len; i++)
        {
            token = _SubListGet(sub_list, i);

            if (token)
            {
                _Subscription *sub = g_hash_table_lookup(catalog->token_map, token);

                if (!sub) continue;

                LSMessage *msg = sub->message;
                const char *unique_name = LSMessageGetSender(msg);
                const char *service_name = LSMessageGetSenderServiceName(msg);
                const char *message_body = LSMessageGetPayload(msg);

                /* create subscribers item and add to sub_array */
                sub_array_item = jobject_create();
                if (sub_array_item == NULL) goto error;

                unique_name_obj = unique_name ? jstring_create_copy(j_cstr_to_buffer(unique_name))
                                              : jstring_empty();
                if (unique_name_obj == NULL) goto error;

                service_name_obj = service_name ? jstring_create_copy(j_cstr_to_buffer(service_name))
                                                : jstring_empty();
                if (service_name_obj == NULL) goto error;

                message_obj = message_body ? jstring_create_copy(j_cstr_to_buffer(message_body))
                                                : jstring_empty();
                if (message_obj == NULL) goto error;

                jobject_put(sub_array_item,
                            J_CSTR_TO_JVAL("unique_name"),
                            unique_name_obj);
                jobject_put(sub_array_item,
                            J_CSTR_TO_JVAL("service_name"),
                            service_name_obj);
                jobject_put(sub_array_item,
                            J_CSTR_TO_JVAL("subscription_message"),
                            message_obj);
                jarray_append(sub_array, sub_array_item);

                sub_array_item = NULL;
                unique_name_obj = NULL;
                service_name_obj = NULL;
                message_obj = NULL;
            }
        }
        jobject_put(cur_obj, J_CSTR_TO_JVAL("key"),
                    key_name);
        jobject_put(cur_obj,
                    J_CSTR_TO_JVAL("subscribers"),
                    sub_array);
        jarray_append(array, cur_obj);
        key_name = NULL;
        cur_obj = NULL;
        sub_array = NULL;
    }

    jobject_put(*ret_obj,
                J_CSTR_TO_JVAL("returnValue"),
                true_obj);
    jobject_put(*ret_obj,
                J_CSTR_TO_JVAL("subscriptions"), array);

    _CatalogUnlock(catalog);

    return true;

error:
    _CatalogUnlock(catalog);

    j_release(ret_obj);
    j_release(&true_obj);
    j_release(&array);

    j_release(&cur_obj);
    j_release(&sub_array);
    j_release(&key_name);

    j_release(&sub_array_item);
    j_release(&unique_name_obj);
    j_release(&service_name_obj);

    return false;
}

/**
 * @} END OF LunaServiceInternals
 * @endcond
 */

/**
 * @addtogroup LunaServiceSubscription
 *
 * @{
 */

/**
 *******************************************************************************
 * @brief Register a callback to be called when subscription is cancelled.
 *
 *  Callback may be called when client cancels subscription via LSCallCancel()
 *  or if the client drops off the bus. The callback won't be called if
 *  LSSubscriptionAdd() failed for any reason.
 *
 * @param  sh              IN  handle to service
 * @param  cancelFunction  IN  callback function
 * @param  ctx             IN  user data to be passed to callback
 * @param  lserror         OUT set on error
 *
 * @return true on success, otherwise false
 *******************************************************************************
 */
bool
LSSubscriptionSetCancelFunction(LSHandle *sh, LSFilterFunc cancelFunction,
                                void *ctx, LSError *lserror)
{
    LSHANDLE_VALIDATE(sh);

    sh->catalog->cancel_function = cancelFunction;
    sh->catalog->cancel_function_ctx = ctx;
    return true;
}

/**
 *******************************************************************************
 * @brief Register a callback to be called when remote service cancelled call.
 *
 * Callback is called when client cancels a call via LSCallCancel().
 * Callback is called whether a call was added to subscriptions catalog or not.
 * This is useful for a case when a notification needs to be recieved without adding
 * subscriber into catalog. Unique token of a message and user context are passed to a function
 * callback as arguments. User can register multiple callback's, which are called in order of registration.
 *
 * @param  sh                   IN  handle to service
 * @param  cancelNotifyFunction IN  callback function
 * @param  ctx                  IN  user data to be passed to callback
 * @param  lserror              OUT set on error
 *
 * @return  true on success, otherwise false
 *******************************************************************************
 */
bool LSCallCancelNotificationAdd(LSHandle *sh,
                                LSCancelNotificationFunc cancelNotifyFunction,
                                void *ctx, LSError *lserror)
{
    LSHANDLE_VALIDATE(sh);

    return _CatalogAddCancelNotification(sh->catalog, cancelNotifyFunction, ctx, lserror);
}

/**
 *******************************************************************************
 * @brief Remove previously registered callback on call cancellation
 *
 *  Function callback is removed from the list without changing relative order of other
 *  elements. Both function callback and context should be the same as for registration
 *
 * @param  sh                   IN  handle to service
 * @param  cancelNotifyFunction IN  callback function
 * @param  ctx                  IN  user data to be passed to callback
 * @param  lserror              OUT set on error
 *
 * @return true on success, otherwise false
 *******************************************************************************
 */
bool LSCallCancelNotificationRemove(LSHandle *sh,
                                LSCancelNotificationFunc cancelNotifyFunction,
                                void *ctx, LSError *lserror)
{
    LSHANDLE_VALIDATE(sh);

    return _CatalogRemoveCancelNotification(sh->catalog, cancelNotifyFunction, ctx, lserror);
}

/**
 *******************************************************************************
 * @brief Add a subscription to a list associated with 'key'.
 *
 * The call may fail if the client has been disconnected. However, if the call
 * succeeds, the code can install callback to get notification about client
 * disconnection or call cancel via LSSubscriptionSetCancelFunction().
 *
 * @param  sh      IN  handle to service
 * @param  key     IN  key
 * @param  message IN  message object
 * @param  lserror OUT set on error
 *
 * @return true on success, otherwise false
 *******************************************************************************
 */
bool
LSSubscriptionAdd(LSHandle *sh, const char *key,
                  LSMessage *message, LSError *lserror)
{
    LSHANDLE_VALIDATE(sh);

    return _CatalogAdd(sh->catalog, key, message, lserror);
}

/**
 *******************************************************************************
 * @brief Acquire an iterator to iterate through the subscription for 'key'.
 *
 * @param  sh        IN  handle to service
 * @param  key       IN  key
 * @param  *ret_iter OUT Acquired iterator
 * @param  lserror   OUT set on error
 *
 * @return true on success, otherwise false
 *******************************************************************************
 */
bool
LSSubscriptionAcquire(LSHandle *sh, const char *key,
                  LSSubscriptionIter **ret_iter, LSError *lserror)
{
    LSHANDLE_VALIDATE(sh);

    _Catalog *catalog = sh->catalog;
    LSSubscriptionIter *iter = g_new0(LSSubscriptionIter, 1);

    _CatalogLock(catalog);
    _SubList *tokens = _CatalogGetSubList_unlocked(catalog, key);
    iter->tokens = _SubListDup(tokens);
    _CatalogUnlock(catalog);

    iter->catalog = catalog;
    iter->index = -1;
    iter->seen_messages = NULL;

    if (ret_iter)
    {
        *ret_iter = iter;
    }

    return true;
}

/**
 *******************************************************************************
 * @brief Frees up resources for LSSubscriptionIter.
 *
 * @param iter IN Subscription iterator to free
 *******************************************************************************
 */
void
LSSubscriptionRelease(LSSubscriptionIter *iter)
{
    GSList *seen_iter = iter->seen_messages;
    while (seen_iter)
    {
        LSMessage *msg = (LSMessage*)seen_iter->data;
        LSMessageUnref(msg);

        seen_iter = seen_iter->next;
    }

    _SubListFree(iter->tokens);
    g_slist_free(iter->seen_messages);
    g_free(iter);
}

/**
 *******************************************************************************
 * @brief Returns whether there is a next item in subscription.
 *
 * @param  iter IN Subscription iterator to check
 *
 * @return true if has next, otherwise false
 *******************************************************************************
 */
bool
LSSubscriptionHasNext(LSSubscriptionIter *iter)
{
    if (!iter->tokens)
    {
        return false;
    }

    return iter->index+1 < _SubListLen(iter->tokens);
}

/**
 *******************************************************************************
 * @brief Obtain the next subscription message.
 *
 * @param  iter IN Subscription iterator to obtain from
 *
 * @retval LSMessage subscription message
 *******************************************************************************
 */
LSMessage *
LSSubscriptionNext(LSSubscriptionIter *iter)
{
    _Subscription *subs = NULL;
    LSMessage *message = NULL;

    iter->index++;
    const char *tok = _SubListGet(iter->tokens, iter->index);
    if (tok)
    {
        subs = _SubscriptionAcquire(iter->catalog, tok);
        if (subs)
        {
            message = subs->message;
            LSMessageRef(message);

            iter->seen_messages =
                g_slist_prepend(iter->seen_messages, message);

            _SubscriptionRelease(iter->catalog, subs);
        }
    }

    return message;
}

/**
 *******************************************************************************
 * @brief Remove the last subscription returned by LSSubscriptionNext().
 *
 * @param iter IN Subscription iterator
 *******************************************************************************
 */
void
LSSubscriptionRemove(LSSubscriptionIter *iter)
{
    const char *tok = _SubListGet(iter->tokens, iter->index);
    if (tok)
    {
        _CatalogRemoveToken(iter->catalog, tok, false);
    }
}

/**
 *******************************************************************************
 * @brief Sends a message to subscription list with name 'key'.
 *
 * @param sh      IN  handle to service
 * @param key     IN  key
 * @param payload IN  some string, usually following json object semantics
 * @param lserror OUT set on error
 *
 * @return true on success, otherwise false
 *******************************************************************************
 */
bool
LSSubscriptionReply(LSHandle *sh, const char *key,
                    const char *payload, LSError *lserror)
{
    _LSErrorIfFail (sh != NULL, lserror, MSGID_LS_INVALID_HANDLE);
    _LSErrorIfFail (payload != NULL, lserror, MSGID_LS_PARAMETER_IS_NULL);

    LSHANDLE_VALIDATE(sh);

    bool retVal = true;
    _Catalog *catalog = sh->catalog;

    _CatalogLock(catalog);

    _SubList *tokens = _CatalogGetSubList_unlocked(catalog, key);
    if (!tokens)
    {
        retVal = true;
        goto cleanup;
    }

    for (int i = 0; i < tokens->len; i++)
    {
        char *tok = g_ptr_array_index(tokens, i);

        _Subscription *subs =
            g_hash_table_lookup(catalog->token_map, tok);
        if (!subs) continue;

        (void) LSMessageRespond(subs->message, payload, lserror);
    }
cleanup:
    _CatalogUnlock(catalog);
    return retVal;
}

/**
 *******************************************************************************
 * @brief If message contains subscribe:true, add the message to subscription
 *        list using the default key '/category/method'.
 *
 *        This is equivalent to LSSubscriptionAdd(sh, key, message, lserror)
 *        where the key is LSMessageGetKind(message).
 *
 * @param  sh         IN  service handle
 * @param  message    IN  message object
 * @param  subscribed OUT
 * @param  lserror    OUT set on error
 *
 * @return true on success, otherwise false
 *******************************************************************************
 */
bool
LSSubscriptionProcess (LSHandle *sh, LSMessage *message, bool *subscribed,
                        LSError *lserror)
{
    JSchemaInfo schemaInfo;
    jschema_info_init(&schemaInfo, jschema_all(), NULL, NULL);

    bool retVal = false;
    bool subscribePayload = false;
    jvalue_ref subObj = NULL;

    const char *payload = LSMessageGetPayload(message);
    jvalue_ref object = jdom_parse(j_cstr_to_buffer(payload), DOMOPT_NOOPT,
                                   &schemaInfo);

    if (jis_null(object))
    {
        _LSErrorSet(lserror, MSGID_LS_INVALID_JSON, -1, "Unable to parse JSON: %s", payload);
        goto exit;
    }

    if (!jobject_get_exists(object, J_CSTR_TO_BUF("subscribe"), &subObj) ||
        subObj == NULL || !jis_boolean(subObj))
    {
        subscribePayload = false;
        /* FIXME: I think retVal should be false, but I don't know if anyone
         * is relying on this behavior. If set to false, make sure to set
         * LSError */
        retVal = true;
    }
    else
    {
        (void)jboolean_get(subObj, &subscribePayload);/* TODO: handle appropriately */
        retVal = true;
    }

    if (subscribePayload)
    {
        const char *key = LSMessageGetKind(message);
        retVal = LSSubscriptionAdd(sh, key, message, lserror);
    }

    if (retVal && subscribePayload)
    {
        *subscribed = true;
    }
    else
    {
        *subscribed = false;
    }

exit:
    j_release(&object);

    return retVal;
}

/**
 *******************************************************************************
 * @brief Posts a message to all in subscription '/category/method'.
 *        This is equivalent to:
 *        LSSubscriptionReply(sh, '/category/method', payload, lserror)
 *
 * @deprecated Please use LSSubscriptionReply() instead.
 *
 * @param  sh       IN  handle to service
 * @param  category IN  category name
 * @param  method   IN  method name
 * @param  payload  IN  some string, usually following json object semantics
 * @param  lserror  OUT set on error
 *
 * @return true on success, otherwise false
 *******************************************************************************
 */
bool
LSSubscriptionPost(LSHandle *sh, const char *category,
                   const char *method,
                   const char *payload, LSError *lserror)
{
    LSHANDLE_VALIDATE(sh);

    bool retVal = false;
    char *key = _LSMessageGetKindHelper(category, method);

    retVal = LSSubscriptionReply(sh, key, payload, lserror);

    g_free(key);
    return retVal;
}

/**
* @brief Returns number of subscribers with name 'key'.
*
* Function can be used to avoid LSSubscriptionIter or payload creation.
*
* @note LSSubscriptionReply has no overhead for empty subscribers list.
*
* @param  sh
* @param  key
*
* @retval unsigned int, number of subscribers
*/
unsigned int LSSubscriptionGetHandleSubscribersCount(LSHandle *sh, const char *key)
{
    LSHANDLE_VALIDATE(sh);

    unsigned retVal = 0;
    _Catalog *catalog = sh->catalog;

    _CatalogLock(catalog);

    _SubList *tokens = _CatalogGetSubList_unlocked(catalog, key);
    if (tokens)
    {
        retVal = tokens->len;
    }

    _CatalogUnlock(catalog);
    return retVal;
}

/**
 * @} END OF LunaServiceSubscription
 */
