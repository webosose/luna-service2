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

#ifndef _LUNASERVICE_H_
#define _LUNASERVICE_H_

#include <stdio.h>
#include <stdbool.h>

#if __cplusplus >= 201103L
#include <cinttypes>
#else
#include <inttypes.h>
#endif

#include <glib.h>

#ifdef WIN32
#define WIN32_LEAN_AND_MEAN
#define NOGDI
#include <winsock2.h>
#else
#include <sys/select.h>
#endif

#include <luna-service2/payload.h>
#include <luna-service2/lunaservice-errors.h>

#ifdef USE_PMLOG_DECLARATION
#include <PmLogLib.h>
#endif

#define LS_DEPRECATED           __attribute__ ((deprecated))
#define LS_DEPRECATED_MSG(msg)  __attribute__ ((deprecated(msg)))

#if !defined(SECURITY_COMPATIBILITY)
#    define LS_DEPRECATED_PUBPRIV  LS_DEPRECATED_MSG("No public/private bus any more")
#else
#    define LS_DEPRECATED_PUBPRIV
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup API_SUMARY API_SUMARY
 * @{
 * Open webOS Luna System Bus library, daemon, and utilities.
 * Luna-service2 (LS2) provides a bus-based IPC mechanism used between components in webOS.
 * Luna-service2 is composed of a client library and a central hub daemon.
 * The client library provides API support to register on the bus and communicate with other components.
 * The hub provides a central clearinghouse for all communication. Utilities for monitoring and debugging the bus are included
 * @}
 */

/**
@addtogroup LunaServiceExample

<h1>LunaService</h1>

<em>Example client usage:</em>

@snippet test_example.c client call


<em>Example service usage.</em>

@snippet test_example.c method implementation

@snippet test_example.c service registration

<em>Storing a message for replying in another thread.</em>
@code

Queue messageQueue;
...

static bool
listContacts(LSHandle *sh, LSMessage *message)
{
     bool retVal;

     LSError lserror;
     LSErrorInit(&lserror);

     LSMessageRef(message);

     queue(messageQueue, message);
}

...

void
SomeOtherThread()
{
    LSError lserror;
    LSErrorInit(&lserror);

    LSMessage *message = dequeue(messageQueue);
    ...
    if (!LSMessageReply(sh, message, "{PAYLOAD IN JSON}", lserror))
    {
        LSErrorLog(loggingCtx, msgId, &lserror);
        LSErrorFree(&lserror);
    }

    ....
}

@endcode
 */

/**
 * @addtogroup LunaService
 * @{
 */

/**
 * @brief Signal category for control messages from the hub
 */
#define HUB_CONTROL_CATEGORY            "/com/palm/hub/control"

/**
 * @brief Signal method that hub emits when the config files scanning
 * has been completed
 */
#define HUB_CONF_SCAN_COMPLETE_METHOD    "configScanComplete"

/** @brief Message token */
typedef unsigned long LSMessageToken;

/**
 * @brief Invalid token number.
 *
 * This is seen if you do LSMessageGetResponseToken() on a message that is not
 * a reply.  It is also a good neutral value to initialize an array of
 * unitialized message tokens.
 */
#define LSMESSAGE_TOKEN_INVALID 0

/**
* @brief Error object which contains information about first
*        error since it was initialized via LSErrorInit.
*/
struct LSError {
    int   error_code;  /**< public error code */
    char *message;     /**< public error message */

    const char *file;  /**< file in which error occurred. */
    int         line;  /**< line on which error occurred. */
    const char *func;  /**< function on which error occurred. */

    void       *padding;  /**< Reserved for future use */
    unsigned long magic;  /**< use as cookie to detect invalid LSErrors  */
};

typedef struct LSError  LSError;

/**
* @brief Handle to service.
*/
typedef struct LSHandle LSHandle;

/**
* @brief Message object.
*/
typedef struct LSMessage        LSMessage;

/**
 * Table registration of callbacks.
 */

/**
* @typedef LSMethodFunction
* @brief Type for method callbacks.
*
* @param sh               handle to service
* @param msg              message object
* @param category_context category context
*
* @retval true if message successfully processed.
* @retval false if some error occurred and you would like the callback to
*               be called again later.
*/
typedef bool (*LSMethodFunction) (LSHandle *sh, LSMessage *msg, void *category_context);


/**
* @typedef LSPropertyGetFunction
* @brief Type for property get callback.
*
* @param sh               handle to service
* @param msg              message object
* @param category_context category context
*
* @return Same as LSMethodFunction()
*/
typedef bool (*LSPropertyGetFunction) (LSHandle *sh, LSMessage *msg, void *category_context);

/**
* @typedef LSPropertySetFunction
* @brief Type for property set callback.
*
* @param sh               handle to service
* @param msg              message object
* @param category_context category context
*
* @return Same as LSMethodFunction()
*/
typedef bool (*LSPropertySetFunction) (LSHandle *sh, LSMessage *msg, void *category_context);

/**
* @brief Flags are used during method definition in a category. Can be used to enable incoming message validation against provided schema
*/
typedef enum {
	LUNA_METHOD_FLAG_DEPRECATED = (1 << 0),

	/**
	 * Automatic params validation according to schema.
	 *
	 * @note you should provide validation schema through
	 *       LSCategorySetDescription
	 */
	LUNA_METHOD_FLAG_VALIDATE_IN = (1 << 1),

	/**
     * Constant to represent method with no flags turned on
	 */
	LUNA_METHOD_FLAGS_NONE = 0,

	/**
	 * Mask that covers all valid method flags. Anything outside treated as an
	 * error.
	 */
	LUNA_METHOD_FLAGS_ALL = LUNA_METHOD_FLAG_DEPRECATED
	                      | LUNA_METHOD_FLAG_VALIDATE_IN
	                      ,
} LSMethodFlags;

/**
 * @brief Flags are used during signal definition in a category. Can be used to mark signal as deprecated
 */
typedef enum {
	LUNA_SIGNAL_FLAG_DEPRECATED = (1 << 0),

	/**
	 * Constant to reprsent method with no flags turned on
	 */
	LUNA_SIGNAL_FLAGS_NONE = 0,
} LSSignalFlags;

/**
 * @brief Flags are used during property definition in a category. Can be used to mark property as deprecated
 */
typedef enum {
	LUNA_PROPERTY_FLAG_DEPRECATED = (1 << 0),

	/**
     * Constant to represent property with no flags turned on
	 */
	LUNA_PROPERTY_FLAGS_NONE = 0,
} LSPropertyFlags;

typedef struct {
    const char *name;		      /**< Method name */
	LSMethodFunction function;  /**< Method function */
	LSMethodFlags flags;		  /**< Method flags */
} LSMethod;

typedef struct {
	const char *name;		    /**<Signal name */
	LSSignalFlags flags;		/**<Signal flags */
} LSSignal;

typedef struct {
	const char *name;		/**<Property name */
	const char *type;		/**<Property value type */
	LSPropertyGetFunction get;	/**<Property get function */
	LSPropertySetFunction set;	/**<Property set function */
	LSPropertyFlags flags;	/**<Property flags */
} LSProperty;

/** @} END OF LunaService */

/**
 * @addtogroup LunaServiceError
 * @{
 */

/* LSError exception style functions */

bool LSErrorInit(LSError *error);
void LSErrorFree(LSError *error);

bool LSErrorIsSet(LSError *lserror);

void LSErrorPrint(LSError *lserror, FILE *out);

#ifdef USE_PMLOG_DECLARATION
void LSErrorLog(PmLogContext context, const char *message_id, LSError *lserror);
#endif
void LSErrorLogDefault(const char *message_id, LSError *lserror);

/** @} END OF LunaServiceError */

/**
 * @addtogroup LunaServiceGlobal
 * @{
 */
void LSIdleTimeout(unsigned int timeout, void (*callback)(void*), void *userdata, GMainContext *ctx);

/**
 * @brief Mark specific message as "weak" (no activity associated with it)
 *
 * Effectively prohibit treatment of this message presence as an activity on LS2
 * bus.
 *
 * @param message  IN  message to mark it as "weak"
 *
 * @note Marking the same LSMessage as inactive more than once is undefined behavior
 * @note Message is treated as active by default. Service with active messages(subscriptions)
 *       will not receive idle timeout callback. Message marked as inavtive does
 *       not prevent idle timeout from being called
 * @see LSIdleTimeout
 */
void LSMessageMarkInactive(LSMessage *message);

/** @} END OF LunaServiceGlobal */

/**
 * @addtogroup LunaServiceRegistration
 * @{
 */

/* Luna Service general functions */

bool LSRegister(const char *name, LSHandle **sh,
                  LSError *lserror);

bool LSRegisterApplicationService(const char *name, const char *app_id, LSHandle **sh,
                  LSError *lserror);

typedef void (*LSDisconnectHandler)(LSHandle *sh, void *user_data);
bool LSSetDisconnectHandler(LSHandle *sh, LSDisconnectHandler disconnect_handler,
                    void *user_data, LSError *lserror);

bool LSRegisterCategory(LSHandle *sh, const char *category,
                   LSMethod      *methods,
                   LSSignal      *langis,
                   LSProperty    *properties, LSError *lserror);

bool LSRegisterCategoryAppend(LSHandle *sh, const char *category,
                   LSMethod      *methods,
                   LSSignal      *langis,
                   LSError *lserror);

bool LSCategorySetData(LSHandle *sh, const char *category,
                       void *user_data, LSError *lserror);

bool LSMethodSetData(LSHandle *sh, const char *category, const char *method,
                     void *user_data, LSError *lserror);

bool LSUnregister(LSHandle *service, LSError *lserror);

const char * LSHandleGetName(LSHandle *sh);

bool LSPushRole(LSHandle *sh, const char *role_path, LSError *lserror);
/** @} END OF LunaServiceRegistration */

/**
 * @addtogroup LunaServiceMessage
 * @{
 */

/* LSMessage (Luna Service Message) functions */

LSHandle * LSMessageGetConnection(LSMessage *message);

void LSMessageRef(LSMessage *message);
void LSMessageUnref(LSMessage *message);

bool LSMessagePrint(LSMessage *lmsg, FILE *out);
bool LSMessageIsHubErrorMessage(LSMessage *message);

const char * LSMessageGetUniqueToken(LSMessage *message);
const char * LSMessageGetKind(LSMessage *message);

const char * LSMessageGetApplicationID(LSMessage *message);

const char * LSMessageGetSender(LSMessage *message);
const char * LSMessageGetSenderServiceName(LSMessage *message);
const char * LSMessageGetSenderExePath(LSMessage *message);
const char * LSMessageGetSenderTrustLevel(LSMessage *message);

const char * LSMessageGetCategory(LSMessage *message);
const char * LSMessageGetMethod(LSMessage *message);

const char * LSMessageGetPayload(LSMessage *message);
LSPayload *LSMessageAccessPayload(LSMessage *message);

bool LSMessageIsSubscription(LSMessage *lsmgs);

LSMessageToken LSMessageGetToken(LSMessage *call);
LSMessageToken LSMessageGetResponseToken(LSMessage *reply);

bool LSMessageRespond(LSMessage *message, const char *reply_payload,
                      LSError *lserror);
bool LSMessageRespondWithPayload(LSMessage *lsmsg, LSPayload *replyPayload,
                                 LSError *lserror);

bool LSMessageReply(LSHandle *sh, LSMessage *lsmsg, const char *replyPayload,
                    LSError *lserror);

/** @} END OF LunaServiceMessage */

/**
 * @addtogroup LunaServiceMainloop
 * @{
 */

/* Mainloop integration functions. */

GMainContext * LSGmainGetContext(LSHandle *sh, LSError *lserror);

bool LSGmainAttach(LSHandle *sh, GMainLoop *mainLoop, LSError *lserror);
bool LSGmainContextAttach(LSHandle *sh, GMainContext *mainContext, LSError *lserror);

bool LSGmainDetach(LSHandle *sh, LSError *lserror);

bool LSGmainSetPriority(LSHandle *sh, int priority, LSError *lserror);

/** @} END OF LunaServiceMainloop */

/**
 * @addtogroup LunaServiceClient
 * @{
 */


/**
* @brief Function callback to be called when serviceName connects or disconnects.
*
* @param  sh             service handle(#LSHandle)
* @param  serviceName    name of service that was brought up/down.
* @param  connected      service was brought up if true.
*
* @return true on success, otherwise false
*/
typedef bool (*LSServerStatusFunc) (LSHandle *sh, const char *serviceName,
                                  bool connected,
                                  void *ctx);

/**
* @brief Callback function called on incoming message.
*
* @param  sh             service handle(#LSHandle)
* @param  reply          incoming message
* @param  void *         context
*
* @return true if message is handled.
*/
typedef bool (*LSFilterFunc) (LSHandle *sh, LSMessage *reply, void *ctx);

/**
* @brief The function will be called when call originator cancels a call.
*
* @param  sh             service handle(#LSHandle)
* @param  uniqueToken    token of cancelled message.
* @param  ctx            context for function callback.
*
* @return true if message is cancelled
*/
typedef bool (*LSCancelNotificationFunc) (LSHandle *sh,
                                  const char *uniqueToken,
                                  void *ctx);

bool LSCallCancelNotificationAdd(LSHandle *sh,
                                LSCancelNotificationFunc cancelNotifyFunction,
                                void *ctx, LSError *lserror);

bool LSCallCancelNotificationRemove(LSHandle *sh,
                                LSCancelNotificationFunc cancelNotifyFunction,
                                void *ctx, LSError *lserror);

bool LSCall(LSHandle *sh, const char *uri, const char *payload,
       LSFilterFunc callback, void *user_data,
       LSMessageToken *ret_token, LSError *lserror);

bool LSCallOneReply(LSHandle *sh, const char *uri, const char *payload,
       LSFilterFunc callback, void *ctx,
       LSMessageToken *ret_token, LSError *lserror);

bool LSCallProxy(LSHandle *sh, const char *origin_exe,
                 const char *origin_id, const char *origin_name,
                 const char *uri, const char *payload,
                 LSFilterFunc callback, void *ctx,
                 LSMessageToken *ret_token, LSError *lserror);

bool LSCallProxyOneReply(LSHandle *sh, const char *origin_exe,
                         const char *origin_id, const char *origin_name,
                         const char *uri, const char *payload,
                         LSFilterFunc callback, void *ctx,
                         LSMessageToken *ret_token, LSError *lserror);

bool LSCallProxyFromApplication(LSHandle *sh, const char *origin_exe,
                                const char *origin_id, const char *origin_name,
                                const char *uri, const char *payload,
                                const char *applicationID,
                                LSFilterFunc callback, void *ctx,
                                LSMessageToken *ret_token, LSError *lserror);

bool LSCallProxyFromApplicationOneReply(LSHandle *sh, const char *origin_exe,
                                        const char *origin_id, const char *origin_name,
                                        const char *uri, const char *payload,
                                        const char *applicationID,
                                        LSFilterFunc callback, void *ctx,
                                        LSMessageToken *ret_token, LSError *lserror);

bool LSCallFromApplication(LSHandle *sh, const char *uri, const char *payload,
       const char *applicationID,
       LSFilterFunc callback, void *ctx,
       LSMessageToken *ret_token, LSError *lserror);

bool LSCallFromApplicationOneReply(
       LSHandle *sh, const char *uri, const char *payload,
       const char *applicationID,
       LSFilterFunc callback, void *ctx,
       LSMessageToken *ret_token, LSError *lserror);

bool LSCallCancel(LSHandle *sh, LSMessageToken token, LSError *lserror);

bool LSCallSetTimeout(
       LSHandle *sh, LSMessageToken token,
       int timeout_ms, LSError *lserror);

/** @} END OF LunaServiceClient */

/**
 * @addtogroup LunaServiceSubscription
 * @{
 */

typedef struct LSSubscriptionIter LSSubscriptionIter;

bool LSSubscriptionProcess (LSHandle *sh, LSMessage *message, bool *subscribed,
                LSError *lserror);

bool LSSubscriptionSetCancelFunction(LSHandle *sh,
                                LSFilterFunc cancelFunction,
                                void *ctx, LSError *lserror);

bool LSSubscriptionAdd(LSHandle *sh, const char *key,
                  LSMessage *message, LSError *lserror);

bool LSSubscriptionAcquire(LSHandle *sh, const char *key,
                  LSSubscriptionIter **ret_iter, LSError *lserror);

void LSSubscriptionRelease(LSSubscriptionIter *iter);

bool LSSubscriptionHasNext(LSSubscriptionIter *iter);

LSMessage *LSSubscriptionNext(LSSubscriptionIter *iter);

void LSSubscriptionRemove(LSSubscriptionIter *iter);

bool LSSubscriptionReply(LSHandle *sh, const char *key,
                    const char *payload, LSError *lserror);

bool LSSubscriptionPost(LSHandle *sh, const char *category,
        const char *method,
        const char *payload, LSError *lserror);

unsigned int LSSubscriptionGetHandleSubscribersCount(LSHandle *sh, const char *key);

/** @} END OF LunaServiceSubscription */

/**
 * @addtogroup LunaServiceSignals
 * @{
 */

bool LSSignalSend(LSHandle *sh, const char *uri, const char *payload,
             LSError *lserror);

bool LSSignalSendNoTypecheck(LSHandle *sh,
            const char *uri, const char *payload, LSError *lserror);

bool LSSignalCall(LSHandle *sh,
         const char *category, const char *methodName,
         LSFilterFunc filterFunc, void *ctx,
         LSMessageToken *ret_token,
         LSError *lserror);

bool LSSignalCallCancel(LSHandle *sh, LSMessageToken token, LSError *lserror);

bool LSRegisterServerStatusEx(LSHandle *sh, const char *serviceName,
                              LSServerStatusFunc func, void *ctxt,
                              void **cookie, LSError *lserror);

bool LSCancelServerStatus(LSHandle *sh, void *cookie, LSError *lserror);

/** @} END OF LunaServiceSignals */


#ifdef __cplusplus
} // extern "C"
#endif

#endif //_LUNASERVICE_H_
