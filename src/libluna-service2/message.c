// Copyright (c) 2008-2018 LG Electronics, Inc.
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

#include "message.h"

#include <glib.h>

#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <pbnjson.h>

#include <luna-service2/lunaservice.h>

#include "base.h"

/**
 * @cond INTERNAL
 * @addtogroup LunaServiceInternals
 * @{
 */

/**
 *******************************************************************************
 * @brief Allocate LSMessage from _LSTransportMessage with a refcount of 1.
 *
 * @param transport_msg
 * @param sh
 *
 * @retval LSMessage, allocated LSMessage
 *******************************************************************************
 */
LSMessage *
_LSMessageNewRef(_LSTransportMessage *transport_msg, LSHandle *sh)
{
    LSMessage *message = g_new0(LSMessage, 1);

    if (transport_msg)
        message->transport_msg = _LSTransportMessageRef(transport_msg);

    message->sh  = sh;
    message->ref = 1;

    return message;
}

void
_LSMessageFree(LSMessage *message)
{
    if (message->transport_msg)
        _LSTransportMessageUnref(message->transport_msg);

    g_free(message->uniqueTokenAllocated);
    g_free(message->kindAllocated);

    g_free(message->methodAllocated);
    g_free(message->payloadAllocated);

#ifdef MEMCHECK
    memset(message, 0xFF, sizeof(LSMessage));
#endif

    g_free(message);
}

void
_LSMessageParsePayload(LSMessage *message)
{
    LS_ASSERT(message != NULL);

    LSPayload *payload = &message->ls_payload;
    _LSTransportMessage *tmsg = message->transport_msg;

    if (_LSTransportMessageGetType(tmsg) == _LSTransportMessageTypeReply ||
        _LSTransportMessageGetType(tmsg) == _LSTransportMessageTypeReplyWithFd)
    {
        const char *data = _LSTransportMessageGetBody(tmsg) + sizeof(LSMessageToken);
        size_t size = _LSTransportMessageGetBodySize(tmsg) - sizeof(LSMessageToken);

        _LSPayloadDeserialize(payload, (void*)data, size);
        payload->fd = _LSTransportMessageGetFd(tmsg);
        return;
    }

    const char *json = _LSTransportMessageGetPayload(tmsg);
    if (json)
    {
        payload->type = PAYLOAD_TYPE_JSON;
        payload->data = (void*)json;
        payload->size = strlen(json) + 1;
    }
    else
    {
        payload->type = PAYLOAD_TYPE_JSON;
        payload->data = (void*)message->payload;
        payload->size = strlen(message->payload) + 1;
    }
}
/**
 * @} END OF LunaServiceInternals
 * @endcond
*/

/**
 * @addtogroup LunaServiceMessage
 *
 * @{
 */

/**
 *******************************************************************************
 * @brief Return a handle to the connection-to-bus through which message was
 *        sent.
 *
 * @param  message IN message
 *
 * @retval LSHandle, handle to the connection-to-bus
 *******************************************************************************
 */
LSHandle *
LSMessageGetConnection(LSMessage *message)
{
    if (!message) return NULL;
    return message->sh;
}

/**
 ********************************************************************************
 * @brief Returns if message is received from public connection to the bus.
 *
 * @param  psh      IN public service
 * @param  message  IN message to check
 *
 * @deprecated Avoid using LSPalmService, use LSHandle instead.
 *
 * @return true on success, otherwise false
 ********************************************************************************/
bool
LSMessageIsPublic(LSPalmService *psh, LSMessage *message)
{
    return (message->sh == psh->public_sh);
}

/**
 *******************************************************************************
 * @brief Increment ref count on message object.  You MUST call this if you wish
 *        to store LSMessage yourself.  A @ref LSMessageRef() MUST be paired
 *        with a @ref LSMessageUnref() lest you leak memory.
 *
 * @param  message IN message to ref
 *******************************************************************************
 */
void
LSMessageRef(LSMessage *message)
{
    LS_ASSERT(message != NULL);
    LS_ASSERT(g_atomic_int_get (&message->ref) > 0);

    g_atomic_int_inc(&message->ref);
}

/**
 *******************************************************************************
 * @brief Decrement ref count on message object.  Object is freed if ref goes to
 *        zero.
 *
 * @param message IN message to unref
 *******************************************************************************
 */
void
LSMessageUnref(LSMessage *message)
{
    LS_ASSERT(message != NULL);
    LS_ASSERT(g_atomic_int_get (&message->ref) > 0);

    if (g_atomic_int_dec_and_test(&message->ref))
    {
        _LSMessageFree(message);
    }
}

/**
 *******************************************************************************
 * @brief Convenience function to pretty print a message.
 *
 * @param  message  IN message to print
 * @param  out      IN file to print
 *
 * @return true on success, otherwise false
 *******************************************************************************
 */
bool
LSMessagePrint(LSMessage *message, FILE *out)
{
    _LSErrorIfFail(NULL != message, NULL, MSGID_LS_MSG_ERR);

    fprintf(out, "%s/%s <%s>\n",
        LSMessageGetCategory(message),
        LSMessageGetMethod(message),
        LSMessageGetPayload(message));

    return true;
}

/**
 *******************************************************************************
 * @brief Returns true if the message is an error message from the hub.
 *
 * @param  message IN message to chech
 *
 * @return true, if message is error message from hub, otherwise false
 *******************************************************************************
 */
bool
LSMessageIsHubErrorMessage(LSMessage *message)
{
    if (!message) return false;

    const char *category = LSMessageGetCategory(message);

    if (!category) return false;

    return (strcmp(category, LUNABUS_ERROR_CATEGORY) == 0);
}

/**
 *******************************************************************************
 * @brief Get the method name of the message.
 *
 * This only applies to request messages on the service side like method call,
 * method cancel, signal call. Doesn't apply to response messages.
 *
 * @param  message IN message
 *
 * @retval const char*, method name
 *******************************************************************************
 */
const char *
LSMessageGetMethod(LSMessage *message)
{
    _LSErrorIfFail(NULL != message, NULL, MSGID_LS_MSG_ERR);

    if (message->method) return message->method;

    message->method = _LSTransportMessageGetMethod(message->transport_msg);

    return message->method;
}

/**
 *******************************************************************************
 * @brief Obtain the application's ID.
 *
 * This only applies to JS Applications' @ref LSCallFromApplication().
 *
 * @param  message IN message
 *
 * @retval const char*, application id
 *******************************************************************************
 */
const char *
LSMessageGetApplicationID(LSMessage *message)
{
    const char *ret = _LSTransportMessageGetAppId(message->transport_msg);

    /* match previous semantics */
    if (ret != NULL && *ret == '\0')
    {
        return NULL;
    }
    else
    {
        return ret;
    }
}

/**
 *******************************************************************************
 * @brief Obtain a unique token identifying the sender.
 *
 * @param  message IN message
 *
 * @retval const char*, sender
 *******************************************************************************
 */
const char *
LSMessageGetSender(LSMessage *message)
{
    _LSErrorIfFail(NULL != message, NULL, MSGID_LS_MSG_ERR);

    const char *sender = _LSTransportMessageGetSenderUniqueName(message->transport_msg);

    return sender;
}

/**
 *******************************************************************************
 * @brief Get the name of the service that sent the message. (NULL if the
 *        sender didn't register a service name)
 *
 * @param message IN message
 *
 * @retval service_name if service sending the message has a name
 * @retval NULL otherwise
 *******************************************************************************
 */
const char *
LSMessageGetSenderServiceName(LSMessage *message)
{
    _LSErrorIfFail(NULL != message, NULL, MSGID_LS_MSG_ERR);

    const char *service_name = _LSTransportMessageGetSenderServiceName(message->transport_msg);

    return service_name;
}

/**
 *******************************************************************************
 * @brief Get the unique serial of this message. Do not confuse with
 *        LSMessageGetResponseToken().
 *
 * @param message IN message
 *
 * @retval LSMessageToken, message token
 *******************************************************************************
 */
LSMessageToken
LSMessageGetToken(LSMessage *message)
{
    _LSErrorIfFail(NULL != message, NULL, MSGID_LS_MSG_ERR);

    LSMessageToken serial = _LSTransportMessageGetToken(message->transport_msg);
    return serial;
}

/**
 *******************************************************************************
 * @brief Get the response token associated with this message this will match
 * with the LSMessageGetToken() of the original call.
 *
 * For signals, the response token is supplanted with the original token
 * returned from LSSignalCall().
 *
 * @param  reply IN message
 *
 * @retval LSMessageToken, message token
 *******************************************************************************
 */
LSMessageToken
LSMessageGetResponseToken(LSMessage *reply)
{
    _LSErrorIfFail(NULL != reply, NULL, MSGID_LS_MSG_ERR);

    if (reply->responseToken)
        return reply->responseToken;

    reply->responseToken = _LSTransportMessageGetReplyToken(reply->transport_msg);

    return reply->responseToken;
}

/**
 *******************************************************************************
 * @brief Get the category of this message.
 *
 * This only applies to request messages on the service side like method call,
 * method cancel, signal call. Doesn't apply to response messages.
 *
 * @param  message IN message
 *
 * @retval const char*, category
 *******************************************************************************
 */
const char *
LSMessageGetCategory(LSMessage *message)
{
    _LSErrorIfFail(NULL != message, NULL, MSGID_LS_MSG_ERR);

    if (message->category)
        return message->category;

    message->category = _LSTransportMessageGetCategory(message->transport_msg);

    return message->category;
}

/**
 *******************************************************************************
 * @brief Get the payload of this message.
 *
 * @param  message IN message
 *
 * @retval const char*, payload
 *******************************************************************************
 */
const char *
LSMessageGetPayload(LSMessage *message)
{
    _LSErrorIfFail(message != NULL, NULL, MSGID_LS_MSG_ERR);

    if (message->payload)
    {
        return message->payload;
    }

    message->payload = LSPayloadGetJson(LSMessageAccessPayload(message));

    return message->payload;
}

/**
 *******************************************************************************
 * @brief Get the payload of this message.
 *
 * @param  message IN message
 *
 * @retval const char*, payload
 *******************************************************************************
 */
LSPayload*
LSMessageAccessPayload(LSMessage *message)
{
    _LSErrorIfFail(message != NULL, NULL, MSGID_LS_MSG_ERR);

    return &message->ls_payload;
}

/**
 *******************************************************************************
 * @brief If message contains a fd, get it.
 *
 * @param  message IN message
 *
 * @retval int, file descriptor
 *******************************************************************************
 */
int LSMessageGetFd(LSMessage *message)
{
    _LSErrorIfFail(message != NULL, NULL, MSGID_LS_MSG_ERR);

    return _LSTransportMessageGetFd(message->transport_msg);
}

/**
 *******************************************************************************
 * @brief Get the payload of the message as a JSON object.
 *
 * @deprecated Do NOT use this function anymore. It now returns NULL always.
 * Use LSMessageGetPayload() and use pbnjson (https://wiki.palm.com/display/CoreOS/pbnjson)
 * to parse the JSON.
 *
 * @param  message IN message
 *
 * @retval NULL always
 *******************************************************************************
 */
LS_DEPRECATED void*
LSMessageGetPayloadJSON(LSMessage  *message)
{
    _LSErrorIfFailMsg(NULL, NULL, MSGID_LS_DEPRECATED, LS_ERROR_CODE_DEPRECATED,
                      LS_ERROR_TEXT_DEPRECATED);
    return NULL;
}

/**
 *******************************************************************************
 * @brief Checks if the message has subscription field with subscribe=true
 *
 * @param message IN message
 *
 * @return true if has subscribe=true, false otherwise
 *******************************************************************************
 */
bool
LSMessageIsSubscription(LSMessage *message)
{
    JSchemaInfo schemaInfo;
    jschema_info_init(&schemaInfo, jschema_all(), NULL, NULL);

    bool ret = false;
    jvalue_ref sub_object = NULL;
    const char *payload = LSMessageGetPayload(message);

    jvalue_ref object = jdom_parse(j_cstr_to_buffer(payload), DOMOPT_NOOPT,
                                   &schemaInfo);
    if (jis_null(object))
        goto exit;

    if (!jobject_get_exists(object, J_CSTR_TO_BUF("subscribe"),
                            &sub_object) || sub_object == NULL)
        goto exit;

    _LSErrorGotoIfFail(exit, jis_boolean(sub_object), NULL, MSGID_LS_INVALID_JSON, -1);

    (void)jboolean_get(sub_object, &ret); /* TODO: handle appropriately */

exit:
    j_release(&object);
    return ret;
}

#ifdef LS_VALIDATE_REPLIES
static
void validate_reply(LSMessage *msg, const char *reply)
{
    const char *const REPLY_TAG = "REPLY_FORMAT_ERROR";

    raw_buffer ec_key = j_cstr_to_buffer("errorCode");
    raw_buffer et_key = j_cstr_to_buffer("errorText");
    raw_buffer sc_key = j_cstr_to_buffer("subscribed");
    raw_buffer rv_key = j_cstr_to_buffer("returnValue");

    JSchemaInfo schema_info;
    jschema_info_init(&schema_info, jschema_all(), NULL, NULL);

    const char* format  = NULL;
    const char* kind    = LSMessageGetKind(msg);
    const char* service = LSHandleGetName(LSMessageGetConnection(msg));

    if (!service)
    {
        service = "(null)";
    }

    char from[strlen(service) + strlen_safe(kind) + 2];
    from[0] = 0;

    strcat(from, service);
    if (kind)
    {
        if (kind[0] != '/')
        {
            strcat(from, "/");
        }
        strncat(from, kind, strlen(kind));
    }

    jvalue_ref parsed = jdom_parse(j_cstr_to_buffer(reply),
            DOMOPT_INPUT_OUTLIVES_DOM | DOMOPT_INPUT_NOCHANGE | DOMOPT_INPUT_NULL_TERMINATED, &schema_info);
    if (jis_valid(parsed))
    {
        if (jis_object(parsed))
        {
            jvalue_ref rv_value;
            if (jobject_get_exists(parsed, rv_key, &rv_value) && jis_boolean(rv_value))
            {
                bool rv_native;
                jvalue_ref ec_value, et_value, sc_value;

                bool ec_exist = jobject_get_exists(parsed, ec_key, &ec_value);
                bool et_exist = jobject_get_exists(parsed, et_key, &et_value);

                // first check that message has request with 'subscribe' key
                bool is_subscription = LSMessageIsSubscription(msg);
                // then check that is 'subscribed' key in response
                bool sc_exist = jobject_get_exists(parsed, sc_key, &sc_value);

                (void)jboolean_get(rv_value, &rv_native);

                if (rv_native)
                {
                    if (ec_exist || et_exist)
                    {
                        format = "%s Reply \"%s\" to \"%s\" has success flag, but \"errorCode\" or \"errorText\" are present";
                    }
                }
                else
                {
                    if (!ec_exist || !et_exist)
                    {
                        format = "%s Reply \"%s\" to \"%s\" has failure flag, but \"errorCode\" or \"errorText\" aren't present";
                    }
                    else if (!ec_exist || !jis_number(ec_value))
                    {
                        format = "%s Reply \"%s\" to \"%s\" has failure flag, but it hasn't key \"errorCode\" with numerical value";
                    }
                    else if (!et_exist || !jis_string(et_value))
                    {
                        format = "%s Reply \"%s\" to \"%s\" has failure flag, but it hasn't key \"errorText\" with string value";
                    }
                }

                if (format)
                {
                    LOG_LS_DEBUG(format, REPLY_TAG, reply, from);
                    format = NULL;
                }

                if (is_subscription && (!sc_exist || !jis_boolean(sc_value)))
                {
                    format = "%s Reply \"%s\" to \"%s\" is subscription message, but it hasn't key \"subscribed\" with boolean value";
                }
            }
            else
            {
                format = "%s Reply \"%s\" to \"%s\" hasn't key \"returnValue\" with boolean value";
            }
        }
        else
        {
            format = "%s Reply \"%s\" to \"%s\" is not json object";
        }

        j_release(&parsed);
    }
    else
    {
        format = "%s Reply \"%s\" to \"%s\" is not valid json object";
    }

    if (format)
    {
        LOG_LS_DEBUG(format, REPLY_TAG, reply, from);
    }
}
#endif //LS_VALIDATE_REPLIES

/**
 *******************************************************************************
 * @brief Send a reply to message using the same bus that message came from.
 *
 * @param  message   IN  message
 * @param  json      IN  payload to send
 * @param  lserror   OUT set on error
 *
 * @return true on success, otherwise false
 *******************************************************************************
 */
bool
LSMessageRespond(LSMessage *message, const char *json, LSError *lserror)
{
    LSHANDLE_VALIDATE(LSMessageGetConnection(message));

    _LSErrorIfFail(message != NULL, lserror, MSGID_LS_MSG_ERR);
    _LSErrorIfFail(json != NULL, lserror, MSGID_LS_PARAMETER_IS_NULL);

    if (unlikely(_ls_enable_utf8_validation))
    {
        if (!g_utf8_validate(json, -1, NULL))
        {
            _LSErrorSet(lserror, MSGID_LS_INVALID_JSON, -EINVAL, "%s: payload is not utf-8", __FUNCTION__);
            return NULL;
        }
    }

    if (unlikely(json[0] == '\0'))
    {
        _LSErrorSet(lserror, MSGID_LS_INVALID_JSON, -EINVAL, "Empty payload is not valid JSON. Use {}");
        return NULL;
    }

    bool retVal = _LSTransportSendReplyString(message->transport_msg, _LSTransportMessageTypeReply, json, lserror);
#ifdef LS_VALIDATE_REPLIES
    validate_reply(message, json);
#endif
    return retVal;
}

/**
 *******************************************************************************
 * @brief Send a reply to message with a payload.
 *
 * @param  message  IN  message
 * @param  payload  IN  payload to send
 * @param  lserror  OUT set on error
 *
 * @return true on success, otherwise false
 *******************************************************************************
 */
bool LSMessageRespondWithPayload(LSMessage *message, LSPayload *payload, LSError *lserror)
{
    LSHANDLE_VALIDATE(LSMessageGetConnection(message));

    _LSErrorIfFail(message != NULL, lserror, MSGID_LS_MSG_ERR);
    _LSErrorIfFail(payload != NULL, lserror, MSGID_LS_PARAMETER_IS_NULL);

    if (DEBUG_TRACING)
    {
        LOG_LS_DEBUG("TX: LSMessageReply token <<%ld>>", LSMessageGetToken(message));
    }

    bool retVal = _LSTransportSendReply(message->transport_msg, payload, lserror);
#ifdef LS_VALIDATE_REPLIES
    if (strcmp(LSPayloadGetDataType(payload), PAYLOAD_TYPE_JSON) == 0)
    {
        size_t size;
        validate_reply(message, (const char *)LSPayloadGetData(payload, &size));
    }
#endif
    return retVal;
}

/**
 *******************************************************************************
 * @brief Send a reply to a message using the bus identified by LSHandle.
 *
 *        To use the same bus upon which the message arrived, it is
 *        recommended to use LSMessageRespond().
 *
 * @param  sh      IN  handle to service
 * @param  lsmsg   IN  message
 * @param  json    IN  json as payload
 * @param  lserror OUT set one error
 *
 * @return true on success, otherwise false
 ******************************************************************************/
bool
LSMessageReply(LSHandle *sh, LSMessage *lsmsg, const char *json, LSError *lserror)
{
    LSHANDLE_VALIDATE(sh);

    _LSErrorIfFail(lsmsg != NULL, lserror, MSGID_LS_MSG_ERR);
    _LSErrorIfFail(json != NULL, lserror, MSGID_LS_PARAMETER_IS_NULL);

#ifdef SECURITY_COMPATIBILITY
    if (unlikely(LSMessageGetConnection(lsmsg) != sh))
    {
        _LSErrorSet(lserror, MSGID_LS_INVALID_BUS, -EINVAL,
                    "%s: You are replying to message on different bus.\n"
                    " If you can't identify which bus, "
                    "try LSMessageRespond() instead.",
                    __FUNCTION__);
        return false;
    }
#else
    LS_ASSERT(LSMessageGetConnection(lsmsg) == sh);
#endif //SECURITY_COMPATIBILITY

    return LSMessageRespond(lsmsg, json, lserror);
}

/**
 *******************************************************************************
 * @brief Send a reply.
 *
 * @param  sh            IN  handle to service
 * @param  lsmsg         IN  message
 * @param  replyPayload  IN  payload to send
 * @param  lserror       OUT set on error
 *
 * @deprecated Use @ref LSMessageReply() instead.
 *
 * @return true on success, otherwise false
 *******************************************************************************
 */
LS_DEPRECATED bool
LSMessageReturn(LSHandle *sh, LSMessage *lsmsg, const char *replyPayload,
                LSError *lserror)
{
    _LSErrorSet(lserror, MSGID_LS_DEPRECATED, LS_ERROR_CODE_DEPRECATED, LS_ERROR_TEXT_DEPRECATED);
    return false;
}

/**
 *******************************************************************************
 * @brief Returns a string that uniquely represents this message.
 *
 * @param  message IN message
 *
 * @retval const char*, token
 *******************************************************************************
 */
const char *
LSMessageGetUniqueToken(LSMessage *message)
{
    if (!message)
        return NULL;

    if (message->uniqueTokenAllocated)
        return message->uniqueTokenAllocated;

    const char *sender = LSMessageGetSender(message);
    LSMessageToken token = LSMessageGetToken(message);

    message->uniqueTokenAllocated = g_strdup_printf("%s.%ld", sender, token);

    return message->uniqueTokenAllocated;
}

/**
 *******************************************************************************
 * @brief Returns the kind of the message (i.e. category + method).
 *
 * @param  message IN message
 *
 * @retval const char*, kind of the message
 *******************************************************************************
 */
const char *
LSMessageGetKind(LSMessage *message)
{
    if (!message)
        return NULL;
    if (message->kindAllocated)
        return message->kindAllocated;

    const char *category = LSMessageGetCategory(message);
    const char *method = LSMessageGetMethod(message);

    message->kindAllocated = _LSMessageGetKindHelper(category,method);

    return message->kindAllocated;
}

char *
_LSMessageGetKindHelper(const char *category, const char *method)
{
    char *key = NULL;

    if (!category)
    {
        category = "";
    }

    key = g_build_filename(category, method, NULL);

    return key;
}

bool LSMessageIsConnected(LSMessage *msg)
{
    return msg->transport_msg->client->state != _LSTransportClientStateDisconnected;
}

/**
 * @} END OF LunaServiceMessage
 */
