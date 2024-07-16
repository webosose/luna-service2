// Copyright (c) 2008-2023 LG Electronics, Inc.
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
#include <pbnjson.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <pbnjson/c/jtypes.h>
#include <luna-service2/lunaservice.h>

#include <luna-service2/payload.h>
#include "simple_pbnjson.h"
#include "base.h"
#include "category.h"
#include "message.h"
#include "subscription.h"
#include "debug_methods.h"

#include "clock.h"
#include "log.h"
#include "transport_priv.h"
#include "transport.h"
#ifdef SECURITY_HACKS_ENABLED
#include "security_hacks.h"
#endif

#include <dlfcn.h>

#include <pmtrace_ls2.h>

#define ENHANCED_ACG
#define DEFAULT_TRUST_LEVEL "dev"

/** @cond INTERNAL */

/* FIXME -- create a callmap.h header file (this function is in callmap.c */
void _LSHandleMessageFailure(_LSTransportMessage *message, _LSTransportMessageFailureType failure_type, void *context);
void _LSDisconnectHandler(_LSTransportClient *client, _LSTransportDisconnectType type, void *context);
bool _LSHandleReply(LSHandle *sh, _LSTransportMessage *transport_msg);
#ifdef ENHANCED_ACG
static LSMessageHandlerResult _LSCheckProvidedTrustedGroups(LSHandle *sh,
    _LSTransportClient *client, LSMethodEntry *method);
#endif
/** @endcond */

/**
 * @defgroup LunaService Luna Service API
 * @ingroup Luna
 */

/**
 * @defgroup LunaServiceExample Example of how to use Luna Service
 * @ingroup LunaService
 */

/**
 * @defgroup LunaServiceClient LunaServiceClient
 * @ingroup  LunaService
 *
 * @brief Luna Service Client-side API is used for communication on LS2 bus.
 * The API allows to register on a bus, register own methods, call methods of other LS2 clients.
 *
 * @cond INTERNAL
 * @defgroup LunaServiceClientInternals The internals of LunaServiceClient
 * @ingroup  LunaServiceClient
 * @endcond
 */

/**
 * @defgroup LunaServiceRegistration Luna Service registration functions
 * @ingroup LunaService
 */

/**
 * @defgroup LunaServiceSignals LunaService signals API
 * @ingroup LunaService
 */

/**
 * @defgroup LunaServiceSubscription LunaService subscription APIs
 * @ingroup  LunaService
 */

/**
 * @defgroup LunaServiceMessage Luna Service Messages
 * @ingroup LunaService
 */

/**
 * @defgroup LunaServiceMainloop Luna Service glib mainloop support
 * @ingroup LunaService
 */

/**
 * @defgroup LunaServiceUtils Luna Service miscellaneous utilities
 * @ingroup LunaService
 */

/**
 * @defgroup LunaServiceError Luna Service error handling
 * @ingroup LunaService
 */

/**
 * @cond INTERNAL
 * @defgroup LunaServiceInternals The internals of LunaService
 * @ingroup  LunaService
 * @endcond
 */

/** Enable UTF8 validation on the payload */
bool _ls_enable_utf8_validation = false;

/** Map service name to transport to register multiple handles for a single transport */
static GHashTable *transport_map = NULL;

/** Lock for the transport map */
static pthread_rwlock_t transport_map_lock = PTHREAD_RWLOCK_INITIALIZER;

/** Idle timeout stuff */
/** Activity flag, raised on recv/accept */
volatile gboolean activity = true;
/** Number of holders (messages and send watches) */
volatile int activity_num = 0;
static struct
{
    void (*cb)(void*);
    void *data;
} idle_callback;

void
LSDebugLogIncoming(const char *where, _LSTransportMessage *message)
{
    if (DEBUG_TRACING)
    {
        G_GNUC_UNUSED LSMessageToken token = _LSTransportMessageGetReplyToken(message);
        const char *sender_service_name = _LSTransportMessageGetSenderServiceName(message);
        if (!sender_service_name) sender_service_name = "(null)";
        const char *sender_unique_name = _LSTransportMessageGetSenderUniqueName(message);
        if (!sender_unique_name) sender_unique_name = "(null)";

        if (DEBUG_VERBOSE)
        {
            const char *payload = _LSTransportMessageGetPayload(message);
            if (!payload) payload = "(null)";

            LOG_LS_DEBUG("RX: %s token <<%ld>> sender: %s sender_unique: %s payload: %s",
                    where, token, sender_service_name, sender_unique_name, payload);
        }
        else
        {
            LOG_LS_DEBUG("RX: %s token <<%ld>> sender: %s sender_unique: %s",
                    where, token, sender_service_name, sender_unique_name);
        }
    }
}

#ifdef LSHANDLE_CHECK
inline void
_lshandle_validate(LSHandle *sh)
{
    if (sh)
    {
        if (sh->history.magic_state_num != LSHANDLE_MAGIC_STATE_VALID)
        {
            Dl_info create_info;
            Dl_info destroy_info;
            G_GNUC_UNUSED bool create_info_valid = false;
            G_GNUC_UNUSED bool destroy_info_valid = false;

            if (sh->history.creator_ret_addr)
            {
                create_info_valid = dladdr(sh->history.creator_ret_addr, &create_info);
            }

            if (sh->history.destroyer_ret_addr)
            {
                destroy_info_valid = dladdr(sh->history.destroyer_ret_addr, &destroy_info);
            }

            LOG_LS_ERROR(MSGID_LS_INVALID_HANDLE, 5,
                    PMLOGKFV("HANDLER", "%p", sh),
                    PMLOGKS("CREATE_DLI_FNAME", create_info_valid ? create_info.dli_fname : "(unknown)"),
                    PMLOGKS("CREATE_DLI_SNAME", create_info_valid ? create_info.dli_sname : "(unknown)"),
                    PMLOGKS("DESTR_DLI_FNAME", destroy_info_valid ? destroy_info.dli_fname : "(unknown)"),
                    PMLOGKS("DESTR_DLI_SNAME", destroy_info_valid ? destroy_info.dli_sname : "(unknown)"),
                    "%s: Invalid handle", __func__);
            LS_ASSERT(!"Invalid LSHandle");
        }
    }
}
#endif

/**
 * @cond INTERNAL
 * @addtogroup LunaServiceInternals
 * @{
 */

struct GlobalState
{
    pthread_once_t  key_once;
    pthread_mutex_t lock;
};

static struct GlobalState state =
{
    .key_once = PTHREAD_ONCE_INIT,
    .lock     = PTHREAD_MUTEX_INITIALIZER,
};

/**
 *******************************************************************************
 * @brief Global lock used exclusively for initialization.
 *******************************************************************************
 */
void
_LSGlobalLock()
{
    pthread_mutex_lock(&state.lock);
}

/**
 *******************************************************************************
 * @brief Global unlock used exclusively for initialization.
 *******************************************************************************
 */
void
_LSGlobalUnlock()
{
    pthread_mutex_unlock(&state.lock);
}

/**
 *******************************************************************************
 * @brief Called once to initialize the Luna Service world.
 *******************************************************************************
 */
static void
_LSInit(void)
{
    char *ls_debug = getenv("LS_DEBUG");
    if (ls_debug)
    {
        _ls_debug_tracing = atoi(ls_debug);
        if (_ls_debug_tracing > 1)
        {
            PmLogSetContextLevel(PmLogGetLibContext(), kPmLogLevel_Debug);
            LOG_LS_DEBUG("Log mode enabled to level %d", _ls_debug_tracing);
        }
    }

    if (getenv("LS_ENABLE_UTF8"))
    {
        _ls_enable_utf8_validation = true;
        LOG_LS_DEBUG("Enable UTF8 validation on payloads");
    }

    transport_map = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
}

bool
_LSErrorSetFunc(LSError *lserror,
                const char *file, int line, const char *function,
                int error_code, const char *error_message, ...)
{
    if (!lserror) return true;

    // don't set an error that is already set.
    if (LSErrorIsSet(lserror))
    {
        return true;
    }

    lserror->file = file;
    lserror->line = line;
    lserror->func = function;
    lserror->error_code    =  error_code;

    va_list args;
    va_start (args, error_message);

    lserror->message = g_strdup_vprintf(error_message, args);

    va_end (args);

    return true;
}

/**
 *******************************************************************************
 * @brief Use when the error_message is not a printf-style string
 * (error_message could contain printf() escape sequences)
 *
 * @param  lserror
 * @param  file
 * @param  line
 * @param  function
 * @param  error_code
 * @param  error_message
 *
 * @return true on success, otherwise false
 *******************************************************************************
 */
bool
_LSErrorSetFuncLiteral(LSError *lserror,
                       const char *file, int line, const char *function,
                       int error_code, const char *error_message)
{
    if (!lserror) return true;

    // don't set an error that is already set.
    if (LSErrorIsSet(lserror))
    {
        return true;
    }

    lserror->file = file;
    lserror->line = line;
    lserror->func = function;
    lserror->error_code = error_code;

    lserror->message = g_strdup(error_message);

    return true;
}

bool
_LSErrorSetFromErrnoFunc(LSError *lserror,
                         const char *file, int line, const char *function,
                         int error_code)
{
    char err_buf[256];
    const char* ret = strerror_r(errno, err_buf, sizeof(err_buf));
    return _LSErrorSetFunc(lserror, file, line, function, error_code, "%s", ret);
}

/** @brief Check if required ACG (of caller) intersect with provided ACG (of the service).
 *
 * Every call is tested against ACG by the receiving part. Bitmasks for ACG seem to be
 * a good choice for good performance.
 *
 * @param[in] provides  Bit set of provided ACG
 * @param[in] requires  Bit set of required ACG
 * @param[in] size      Size of bit set in bitmask words
 *
 * @retval true If bit sets @p provides and @p requires have common bits
 * @retval false If there's no common bit in @p provides and @p requires
 */
static inline bool
_LSSecurityCheckGroup(const LSTransportBitmaskWord *provides,
                      const LSTransportBitmaskWord *requires,
                      int size)
{
    if (!provides || !requires)
        return false;

    LOG_LS_DEBUG("[%s]provide : %d, requires : %d \n", __func__, *provides, *requires);
    int i = 0;
    for (; i < size; i++)
    {
        if (provides[i] & requires[i]) {
            LOG_LS_DEBUG("[%s] Group CHeck pass[provides: %d] [requires: %d][pos: %d] \n",
            __func__, provides[i], requires[i], i);
           return true;
        }
    }
    return false;
}

/** @brief Check if required ACG (of caller) intersect with provided ACG (of the service).
 *
 * Every call is tested against ACG by the receiving part. Bitmasks for ACG seem to be
 * a good choice for good performance.
 *
 * @param[in] provides  Bit set of provided ACG
 * @param[in] requires  Bit set of required ACG
 * @param[in] size      Size of bit set in bitmask words
 *
 * @retval true If bit sets @p provides and @p requires have common bits
 * @retval false If there's no common bit in @p provides and @p requires
 */
static inline bool
_LSSecurityCheckTrustLevel(const char* provided_trust_level_string,
                           const char* required_trust_level_string)
{
    /* Signed and Unsigned app/service criteria to check for trust level
        ----------------------------------------------
        <app/service    |   signed   |  unsigned     |
        ----------------------------------------------
        signed          |     o      |     o         |
        ----------------------------------------------
        unsigned        |     X      |     o         |
        ----------------------------------------------
    */

    bool isProvidedTrusted = false;
    bool isRequiredTrusted = false;

    if(strcmp(provided_trust_level_string, DEFAULT_TRUST_LEVEL))
        isProvidedTrusted = true;
    if(strcmp(required_trust_level_string, DEFAULT_TRUST_LEVEL))
        isRequiredTrusted = true;

    /* Usigned caller and unsigned callee */
    if (!isProvidedTrusted && !isRequiredTrusted)
    {
        /* Since both are unsigned no trustLevel is specified */
        return true;
    }

    if (!isProvidedTrusted || !isRequiredTrusted)
    {
        /* Unsigned caller and signed callee */
        if(isProvidedTrusted)
            return false;
        /* Signed caller and unsigned callee */
        if(isRequiredTrusted)
            return true;
    }

    /* Trust level hierarchy

                      | oem | part | dev |
                --------------------------
                oem   |  o  |  o   |  o  |
                --------------------------
                part  |  x  |  o   |  o  |
                --------------------------
                dev   |  x  |  x   |  o  |
                --------------------------
    */
    if (!strcmp(provided_trust_level_string, required_trust_level_string)) {
        LOG_LS_DEBUG("[%s] Trust Level Matched \
                     provided_trust_level_string : %s \
                     required_trust_level_string : %s \n",
                     __func__, provided_trust_level_string, required_trust_level_string);
        return true;
    }
    else if(!strcmp("oem", required_trust_level_string))
    {
        LOG_LS_DEBUG("[%s]Required trust level [%s] superseeds every other trust level \n",
                     __func__, required_trust_level_string);
        return true;
    }
    else if(!strcmp("oem", provided_trust_level_string))
    {
        LOG_LS_DEBUG("[%s]Required trust level [%s] superseeds every other trust level \n",
                     __func__, provided_trust_level_string);
        return false;
    }
    else if(!strcmp("part", required_trust_level_string))
    {
        LOG_LS_DEBUG("[%s]Required trust level [%s] can access other than OEM \n",
        __func__, required_trust_level_string);
        return true;
    }
    else if(!strcmp("part", provided_trust_level_string))
    {
        LOG_LS_DEBUG("[%s]Required trust level [%s] can access other than OEM \n",
        __func__, provided_trust_level_string);
        return false;
    }
    else
    {
        return false;
    }

    // TESTING: just to avoid unstable luna service, till feature, otherwise returns false on mismatch
    return false;
}

static inline gchar *
_LSSecurityGetGroupsStringFromMask(_LSTransport *transport, LSTransportBitmaskWord *mask)
{
    GHashTableIter iter_groups;
    gpointer group, bit;
    GString *groups = g_string_new(NULL);

    g_hash_table_iter_init(&iter_groups, transport->group_code_map);
    while (g_hash_table_iter_next(&iter_groups, &group, &bit)) {
        if (BitMaskTestBit(mask, GPOINTER_TO_INT(bit))) {
            g_string_append(groups, group);
            g_string_append(groups, " ");
        }
    }

    return g_string_free(groups, FALSE);
}

static inline LSMessageHandlerResult
LSCategoryMethodCall(LSHandle *sh, LSCategoryTable *category,
                     _LSTransportClient *client, LSMessage *message)
{
    const char *method_name = LSMessageGetMethod(message);

    /* find the method in the tableHandlers->methods hash */
    LSMethodEntry *method = g_hash_table_lookup(category->methods, method_name);

    if (!method)
    {
        LOG_LS_ERROR(MSGID_LS_NO_METHOD, 1,
                     PMLOGKS("METHOD", method_name),
                     "Couldn't find method: %s", method_name);
        return LSMessageHandlerResultUnknownMethod;
    }

    const char* sender = _LSTransportClientGetServiceName(client);

#ifdef SECURITY_HACKS_ENABLED
    if (_LSIsTrustedService(sender))
    {
        LOG_LS_INFO(MSGID_LS_NOT_AN_ERROR, 0, "Security hacks was applyed for: %s", sender);
    }
    else
#endif
    if (!_LSSecurityCheckGroup(method->security_provided_groups,
                               client->security_required_groups,
                               LSTransportGetSecurityMaskSize(sh->transport)))
    {
        const char *service_name = LSHandleGetName(sh);
        gchar *provided_groups = _LSSecurityGetGroupsStringFromMask(sh->transport, method->security_provided_groups);
        gchar *required_groups = _LSSecurityGetGroupsStringFromMask(sh->transport, client->security_required_groups);
        LOG_LS_WARNING(MSGID_LS_REQUIRES_SECURITY, 4,
                       PMLOGKS("CLIENT", sender ? sender : "(null)"),
                       PMLOGKS("SERVICE", service_name ? service_name : "(null)"),
                       PMLOGKS("CATEGORY", LSMessageGetCategory(message)),
                       PMLOGKS("METHOD", method_name),
                       "Service security groups don't allow method call.\n"
                       "provided_groups: %s\n"
                       "required_groups: %s\n",
                       provided_groups ? provided_groups : "(null)",
                       required_groups ? required_groups : "(null)");
        if (provided_groups)
            g_free(provided_groups);
        if (required_groups)
            g_free(required_groups);
        return LSMessageHandlerResultPermissionDenied;
    }

    LOG_LS_DEBUG("[%s]method_name: %s  method->security_provided_groups: %d, client->security_required_groups: %d, LSTransportGetSecurityMaskSize(sh->transport): %d",
                 __func__, method_name,*method->security_provided_groups, *client->security_required_groups,
                  LSTransportGetSecurityMaskSize(sh->transport));

#ifdef ENHANCED_ACG
    if (_LSCheckProvidedTrustedGroups(sh, client, method) == LSMessageHandlerResultPermissionDenied)
    {
        LOG_LS_WARNING(MSGID_LS_REQUIRES_TRUST, 3,
                       PMLOGKS("SERVICE", sender ? sender : "(null)"),
                       PMLOGKS("CATEGORY", LSMessageGetCategory(message)),
                       PMLOGKS("METHOD", method_name),
                      "Service security groups don't allow method call as trust level does not match");
        return LSMessageHandlerResultPermissionDenied;
    }
#endif

    char* receiver = g_strdup(sh->name ? sh->name : "(null)");
    bool validateCall = method->flags & LUNA_METHOD_FLAG_VALIDATE_IN;

    /* XXX: work-around clients that puts garbage in method flags */
    if (unlikely(validateCall && method->schema_call == NULL))
    {
        validateCall = false;
        LOG_LS_ERROR(MSGID_LS_BAD_VALIDATION_FLAG, 5,
                     PMLOGKS("SENDER", sender),
                     PMLOGKS("SERVICE", receiver),
                     PMLOGKS("CATEGORY", LSMessageGetCategory(message)),
                     PMLOGKS("METHOD", method_name),
                      PMLOGKFV("FLAGS", "%d", method->flags),
                     "Called for method that was declared for validation but wasn't supplied with schema");
    }

    bool validCall = !validateCall || LSCategoryValidateCall(method, message);

    if (unlikely(method->flags & LUNA_METHOD_FLAG_DEPRECATED))
    {
        LOG_LS_WARNING(MSGID_LS_DEPRECATED, 5,
                       PMLOGKS("SENDER", LSMessageGetSenderServiceName(message)),
                       PMLOGKS("SERVICE", client->service_name),
                       PMLOGKS("CATEGORY", LSMessageGetCategory(message)),
                       PMLOGKS("METHOD", method_name),
                       PMLOGKFV("FLAGS", "%X", method->flags),
                       "Deprecated method call");
    }

    // pmtrace point before call a handler
    PMTRACE_SERVER_RECEIVE(sender, receiver, (char*)method_name, LSMessageGetToken(message));

    // TODO prevent DEBUG mode from using CPU and memory
    struct timespec start_time, end_time, gap_time;
    if (DEBUG_TRACING)
    {
        ClockGetTime(&start_time);
    }
    bool handled;

    if (!validCall) /* validation error were sent */
    { handled = true; }
    else if (method->function == NULL) /* no callback were set? */
    { handled = false; }
    else if (method->method_user_data != NULL) /* method context is set. use it instead of category */
    { handled = method->function(sh, message, method->method_user_data); }
    else
    { handled = method->function(sh, message, category->category_user_data); }

    if (DEBUG_TRACING)
    {
        ClockGetTime(&end_time);
        ClockDiff(&gap_time, &end_time, &start_time);
        LOG_LS_DEBUG("TYPE=service handler execution time | TIME=%ld | SERVICE=%s | CATEGORY=%s | METHOD=%s",
                ClockGetMs(&gap_time), receiver, LSMessageGetCategory(message), method_name);
    }

    // pmtrace point after handler
    PMTRACE_SERVER_REPLY(sender, receiver, (char*)method_name, LSMessageGetToken(message));

    g_free(receiver);

    if (!handled)
    {
        LOG_LS_WARNING(MSGID_LS_MSG_NOT_HANDLED, 1,
                       PMLOGKS("METHOD", method_name),
                       "Method wasn't handled!");
        return LSMessageHandlerResultNotHandled;
    }

    return LSMessageHandlerResultHandled;
}

#ifdef ENHANCED_ACG
LSMessageHandlerResult _LSCheckProvidedTrustedGroups(LSHandle *sh,
    _LSTransportClient *client, LSMethodEntry *method)
{
    LSMessageHandlerResult eResult = LSMessageHandlerResultHandled;

    /* Compare the trust level */
    GSList *list = LSTransportGetTrustLevelToGroups(sh->transport);
    if (list)
    {
        bool trustLevelFound = false;
        jvalue_ref providedGroupTrustLevel = NULL;
        jvalue_ref providedGroupsRef = NULL;

        LOG_LS_INFO(MSGID_LS_NOT_AN_ERROR, 0,"Enhanced ACG \n");
        // prepare full methods name for pattern matching
        //char *full_name = g_build_path("/", category_path, m->name, NULL);
        const LSTransportTrustLevelGroupBitmask *TrustLevel_bitmask = NULL;

        /* Get the provided groups and get the mask */
        providedGroupsRef = LSTransportGetGroupsFromMask(sh->transport, method->security_provided_groups);
        if (providedGroupsRef)
        {
            char* providedGroup = NULL;
            for (ssize_t i = 0; i != jarray_size(providedGroupsRef); ++i)
            {
                jvalue_ref jgroup = jarray_get(providedGroupsRef, i);
                raw_buffer provided_raw = jstring_get_fast(jgroup);
                providedGroup = g_strndup(provided_raw.m_str, provided_raw.m_len);
                list = LSTransportGetTrustLevelToGroups(sh->transport);

                for (; list; list = g_slist_next(list))
                {
                    TrustLevel_bitmask = (const LSTransportTrustLevelGroupBitmask *) list->data;

                    /* Default groups like all are added by default which do not have trust level */
                    /* Ignore such groups while checking for trust level */
                    LOG_LS_DEBUG("[%s] providedGroup: %s \n", __func__, providedGroup);

                    if (g_pattern_match_string(TrustLevel_bitmask->group_pattern, providedGroup))
                    {
                        if(TrustLevel_bitmask->trustLevel_group_bitmask)
                        {
                            LOG_LS_INFO(MSGID_LS_NOT_AN_ERROR, 0, "[%s] found group bit mask : %d \n", __func__,
                                               *TrustLevel_bitmask->trustLevel_group_bitmask);
                            providedGroupTrustLevel = LSTransportGetTrustFromMask(sh->transport,
                                                          TrustLevel_bitmask->trustLevel_group_bitmask);
														  													  
							/* Get required group's trust level */
							if(providedGroupTrustLevel)
							{
								char* providedTrustLevel = NULL;
								for (ssize_t i = 0; i != jarray_size(providedGroupTrustLevel); ++i)
								{
									jvalue_ref jgroup = jarray_get(providedGroupTrustLevel, i);
									raw_buffer provided_raw = jstring_get_fast(jgroup);
									providedTrustLevel = g_strndup(provided_raw.m_str, provided_raw.m_len);

									if (!_LSSecurityCheckTrustLevel(providedTrustLevel,
																	client->trust_level_string))
									{
										eResult = LSMessageHandlerResultPermissionDenied;
										LOG_LS_DEBUG("[%s] Tust Not matched [Provided : %s] [required : %s] \n",
													 __func__, providedTrustLevel,
													 client->trust_level_string);
									}
									else
									{
										eResult = LSMessageHandlerResultHandled;
										trustLevelFound = true;
									}
									LOG_LS_DEBUG("LSCategoryMethodCall [ %s]", providedTrustLevel);

									g_free(providedTrustLevel);
									providedTrustLevel = NULL;

									if (LSMessageHandlerResultHandled == eResult)
										break;
								}
								j_release(&providedGroupTrustLevel);
							}                            
                            break;
                        }
                    }
                }
                g_free(providedGroup);
                providedGroup = NULL;

                /* Assumption is that only the group bit of the method is set */
                if(trustLevelFound)
                    break;
            }
            j_release(&providedGroupsRef);
        }
    }

    return eResult;
}
#endif

static LSMessageHandlerResult
_LSHandleMethodCall(LSHandle *sh, _LSTransportMessage *transport_msg)
{
    LSMessageHandlerResult retVal;

    LSMessage *message = _LSMessageNewRef(transport_msg, sh);
    _LSMessageParsePayload(message);

    /* look up the name in tableHandlers */
    GHashTable *categories = sh->tableHandlers;

    const char* category_name = LSMessageGetCategory(message);

    /* find the category in the tableHandlers (LSCategoryTable) */
    LSCategoryTable *category = g_hash_table_lookup(categories, category_name);
    if (!category)
    {
        char *uri = g_build_path("/", sh->name, category_name, LSMessageGetMethod(message), NULL);
        LOG_LS_ERROR(MSGID_LS_NO_CATEGORY, 1,
                     PMLOGKS("CATEGORY", category_name),
                     "Couldn't find category: %s (method call %s -> %s)", category_name,
                     _LSTransportMessageGetSenderServiceName(transport_msg),
                     uri);
        g_free(uri);
        retVal = LSMessageHandlerResultUnknownMethod;
    }
    else
    {
        if (_LSTransportClientAllowInboundCalls(transport_msg->client))
        {
            retVal = LSCategoryMethodCall(sh, category, transport_msg->client, message);
        }
        else
        {
            LOG_LS_WARNING(MSGID_LS_REQUIRES_SECURITY, 3,
                           PMLOGKS("SERVICE", LSMessageGetSenderServiceName(message)),
                           PMLOGKS("CATEGORY", LSMessageGetCategory(message)),
                           PMLOGKS("METHOD", LSMessageGetMethod(message)),
                          "Service '%s' is not allowed to make calls, but trying to call: %s/%s",
                           LSMessageGetSenderServiceName(message), LSMessageGetCategory(message),
                           LSMessageGetMethod(message));

            retVal = LSMessageHandlerResultPermissionDenied;
        }
    }

    LSMessageUnref(message);

    return retVal;
}


/* NOTE: only certain types are handled here -- those that aren't considered
 * "internal" */
static LSMessageHandlerResult
_LSMessageHandler(_LSTransportMessage *message, void *context)
{
    LSMessageHandlerResult retVal = LSMessageHandlerResultHandled;

    switch (_LSTransportMessageGetType(message))
    {
    case _LSTransportMessageTypeMethodCall:
    case _LSTransportMessageTypeCancelMethodCall:
        /* NOTE: the "cancel method call" is handled by the
         * _privateMethods -- _LSPrivateCancel, which is registered for
         * all services by default */
        retVal = _LSHandleMethodCall(context, message);
        break;

    case _LSTransportMessageTypeSignal:
    case _LSTransportMessageTypeReply:
    case _LSTransportMessageTypeReplyWithFd:
    case _LSTransportMessageTypeQueryServiceStatusReply:
    case _LSTransportMessageTypeQueryServiceCategoryReply:
    case _LSTransportMessageTypeServiceDownSignal:
    case _LSTransportMessageTypeServiceUpSignal:
    case _LSTransportMessageTypeError:
    case _LSTransportMessageTypeErrorUnknownMethod:
        /* we're ignoring the return value; we don't really want to
         * send an error reply message to a reply */
        (void) _LSHandleReply(context, message);
        break;

    default:
        LOG_LS_WARNING(MSGID_LS_UNKNOWN_MSG, 1,
                       PMLOGKFV("MSG_TYPE", "%d", _LSTransportMessageGetType(message)),
                       "Received message we don't understand: %d",
                       _LSTransportMessageGetType(message));
        break;
    }

    return retVal;
}

/** @brief Dispatch received message to the correct handle.
 *
 * Legacy code may register two handles (private and public) for the same transport.
 * Thus, every single method call and reply should be correctly routed to the
 * originating handle.
 *
 * @param[in] message
 * @param[in] context Transport, should be substituted by the correct handle when forwarded
 *                    to the callmap.
 * @return Result of message handling
 */
static LSMessageHandlerResult
_LSMessageMuxHandler(_LSTransportMessage *message, void *context)
{
    _LSTransport *transport = (_LSTransport *) context;
    if (transport->is_old_config)
    {
        LSHandle *sh = transport->back_sh[message->raw->header.is_public_bus];
        LSMessageHandlerResult res = (sh) ? _LSMessageHandler(message, sh) : LSMessageHandlerResultNotHandled;
        // If call not successful and caller uses private bus - probably we handle call from new configured service
        // Thus try to process call on public bus as well
        if (!message->raw->header.is_public_bus && LSMessageHandlerResultHandled != res)
        {
            sh = transport->back_sh[true];
            LSMessageHandlerResult new_res = (sh) ? _LSMessageHandler(message, sh) : LSMessageHandlerResultNotHandled;
            res = (LSMessageHandlerResultHandled == new_res) ? new_res : res;
        }
        return res;
    }
    else
    {
        // Transport uses new configuration - only private bus should be processed
        LSHandle *sh = transport->back_sh[false];
        return sh ? _LSMessageHandler(message, sh) : LSMessageHandlerResultNotHandled;
    }
}

/** @brief Forward disconnection to either or both registered legacy handles
 *
 * @param[in] client
 * @param[in] type
 * @param[in] context Transport, should be substituted by the correct handle when forwarded
 *                    to the callmap.
 */
static void
_LSDisconnectMuxHandler(_LSTransportClient *client,
                        _LSTransportDisconnectType type,
                        void *context)
{
    _LSTransport *transport = (_LSTransport *) context;
    if (transport->back_sh[0])
        _LSDisconnectHandler(client, type, transport->back_sh[0]);
    if (transport->back_sh[1])
        _LSDisconnectHandler(client, type, transport->back_sh[1]);
}

/** @brief Forward message failure to the correct handle (public or private)
 *
 * The function is less careful than _LSMessageMuxHandler, because this is anyway
 * temporary code, and message failures are assumed to be rare.
 *
 * @param[in] message
 * @param[in] failure_type
 * @param[in] context Transport, should be substituted by the correct handle when forwarded
 *                    to the callmap.
 */
static void
_LSHandleMessageFailureMux(_LSTransportMessage *message,
                           _LSTransportMessageFailureType failure_type,
                           void *context)
{
    _LSTransport *transport = (_LSTransport *) context;
    LSHandle *sh = transport->back_sh[message->raw->header.is_public_bus];
    if (sh)
        _LSHandleMessageFailure(message, failure_type, sh);
}

/**
 * @} END OF LunaServiceInternals
 * @endcond
 */

/**
 * @addtogroup LunaServiceError
 *
 * @{
 */

/**
 *******************************************************************************
 * @brief Initializes a LSError.
 *
 * @param lserror IN LSError structure to initialize
 *
 * @return true on success, otherwise false
 *******************************************************************************
 */
bool
LSErrorInit(LSError *lserror)
{
    _LSErrorIfFail(lserror != NULL, NULL, MSGID_LS_ERROR_INIT_ERR);

    memset(lserror, 0, sizeof (LSError));

    LS_MAGIC_SET(lserror, LSError);

    return true;
}

/**
 *******************************************************************************
 * @brief Find the status of a LSError
 *
 * @param  lserror IN LSError structure to check
 *
 * @return true if the LSError contains an error code/message.
 *******************************************************************************
 */
bool
LSErrorIsSet(LSError *lserror)
{
    LSERROR_CHECK_MAGIC(lserror);

    return (lserror && lserror->error_code != 0);
}

/**
 *******************************************************************************
 * @brief Convenience function to print a LSError
 *
 * @param lserror IN LSError structure to print
 * @param out     IN handle to file
 *******************************************************************************
 */
void
LSErrorPrint(LSError *lserror, FILE *out)
{
    LSERROR_CHECK_MAGIC(lserror);

    if (lserror)
    {
        fprintf(out, "LUNASERVICE ERROR %d: %s (%s @ %s:%d)\n",
            lserror->error_code, lserror->message,
            lserror->func, lserror->file, lserror->line);
    }
    else
    {
        fprintf(out, "LUNASERVICE ERROR: lserror is NULL. Did you pass in a LSError?");
    }
}

/**
 *******************************************************************************
 * @brief Function to log a LSError with PmLogLib
 *
 * @param context    IN log context
 * @param message_id IN message id
 * @param lserror    IN LSError structure to log
 *******************************************************************************
 */
void
LSErrorLog(PmLogContext context, const char *message_id, LSError *lserror)
{
    LSERROR_CHECK_MAGIC(lserror);

    if (lserror)
    {
        PmLogError(context, message_id, 5,
                   PMLOGKFV("ERROR_CODE", "%d", lserror->error_code),
                   PMLOGKS("ERROR", lserror->message),
                   PMLOGKS("FUNC", lserror->func),
                   PMLOGKS("FILE", lserror->file),
                   PMLOGKFV("LINE", "%d", lserror->line),
                   "LUNASERVICE ERROR");
    }
    else
    {
        LOG_LS_ERROR(MSGID_LS_NULL_LS_ERROR, 0, "lserror is NULL. Did you pass in a LSError?");
    }
}

/**
 *******************************************************************************
 * @brief Function to log a LSError by default
 *
 * @param message_id IN message id
 * @param lserror    IN LSError structure to log
 *******************************************************************************
 */
void
LSErrorLogDefault(const char *message_id, LSError *lserror)
{
    LSERROR_CHECK_MAGIC(lserror);

    if (lserror)
    {
        PmLogError(PmLogGetLibContext(), message_id, 5,
                   PMLOGKFV("ERROR_CODE", "%d", lserror->error_code),
                   PMLOGKS("ERROR", lserror->message),
                   PMLOGKS("FUNC", lserror->func),
                   PMLOGKS("FILE", lserror->file),
                   PMLOGKFV("LINE", "%d", lserror->line),
                   "LUNASERVICE ERROR");
    }
    else
    {
        LOG_LS_ERROR(MSGID_LS_NULL_LS_ERROR, 0, "lserror is NULL. Did you pass in a LSError?");
    }
}

/**
 *******************************************************************************
 * @brief Frees the internal structures of LSError if an error has been handled.
 *        Must be called on an error if set.
 *
 * @param lserror IN LSError structure to free
 *******************************************************************************
 */
void
LSErrorFree(LSError *lserror)
{
    if (lserror)
    {
        LSERROR_CHECK_MAGIC(lserror);
        g_free(lserror->message);

        LSErrorInit(lserror);
    }
}

/** @} END OF LunaServiceError */


/**
 * @addtogroup LunaServiceRegistration
 * @{
 */


static bool
_LSPrivateCancel(LSHandle* sh, LSMessage *message, void *user_data)
{
    bool retVal;
    LSError lserror;
    LSErrorInit(&lserror);

    retVal = _CatalogHandleCancel(sh->catalog, message, &lserror);
    if (!retVal)
    {
        LOG_LSERROR(MSGID_LS_CANT_CANCEL_METH, &lserror);
        LSErrorFree(&lserror);
    }

    return true;
}

static bool
_LSPrivatePing(LSHandle* lshandle, LSMessage *message, void *user_data)
{
    bool retVal;
    LSError lserror;
    LSErrorInit(&lserror);

    const char *ping_string = "{\"returnValue\":true}";
    retVal = LSMessageReply(lshandle, message, ping_string, &lserror);
    if (!retVal)
    {
        LOG_LSERROR(MSGID_LS_CANT_PING, &lserror);
        LSErrorFree (&lserror);
    }

    return true;
}

static LSMethod _privateMethods[] = {
    { "cancel", _LSPrivateCancel},
    { "ping", _LSPrivatePing},
#ifdef SUBSCRIPTION_DEBUG
    { "subscriptions", _LSPrivateGetSubscriptions},
#endif
#ifdef MALLOC_DEBUG
    { "mallinfo", _LSPrivateGetMallinfo},
    { "malloc_trim", _LSPrivateDoMallocTrim},
#endif
#ifdef INTROSPECTION_DEBUG
    { "introspection", _LSPrivateInrospection},
#endif
    { },
};


/**
 *******************************************************************************
 * @brief Set a function to be called if we are disconnected from the bus.
 *
 * @param sh                 IN  handle to service
 * @param disconnect_handler IN  function callback
 * @param user_data          IN  user data to be passed to callback
 * @param lserror            OUT set on error
 *
 * @return true on success, otherwise false
 *******************************************************************************
 */
bool
LSSetDisconnectHandler(LSHandle *sh, LSDisconnectHandler disconnect_handler,
                       void *user_data,
                       LSError *lserror)
{
    _LSErrorIfFail(sh != NULL, lserror, MSGID_LS_INVALID_HANDLE);
    LSHANDLE_VALIDATE(sh);
    sh->disconnect_handler = disconnect_handler;
    sh->disconnect_handler_data = user_data;
    return true;
}

/** @cond INTERNAL */

/*
    We need a common routine one level down from all the public LSRegister* functions
*/
bool
_LSRegisterCommon(const char *name, const char *app_id, LSHandle **ret_sh,
                  bool public_bus,
                  void *call_ret_addr,
                  LSError *lserror)
{
    _LSErrorIfFail(ret_sh != NULL, lserror, MSGID_LS_INVALID_HANDLE);

    pthread_once(&state.key_once, _LSInit);

    _LSTransport *existingTransport = NULL;
    _LSTransport *new_transport = NULL;

    bool is_name_not_empty = name && *name;
    if (is_name_not_empty)
    {
        pthread_rwlock_rdlock(&transport_map_lock);
        existingTransport = g_hash_table_lookup(transport_map, name);
        pthread_rwlock_unlock(&transport_map_lock);
    }

    LSHandle *sh = g_new0(LSHandle, 1);
    if (!sh) goto error;

    sh->is_public_bus = public_bus;

    /* For backward compatibility, convert empty string to NULL */
    if (name && name[0] == '\0')
    {
        name = NULL;
    }

    sh->name        = g_strdup(name);

    LSHANDLE_SET_VALID(sh, call_ret_addr);

    if (existingTransport)
    {
        if (name && *name && existingTransport->back_sh[public_bus])
        {
            _LSErrorSet(lserror, MSGID_LS_REQUEST_NAME, LS_ERROR_CODE_DUPLICATE_NAME, LS_ERROR_TEXT_DUPLICATE_NAME, name);
            goto error;
        }

        sh->transport = existingTransport;
    }
    else
    {
        LSTransportHandlers _LSTransportHandler =
        {
            .msg_handler = _LSMessageHandler,
            .msg_context = sh,
            .disconnect_handler = _LSDisconnectHandler,
            .disconnect_context = sh,
            .message_failure_handler = _LSHandleMessageFailure,
            .message_failure_context = sh
        };

        if (_LSTransportInit(&new_transport, sh->name, app_id, &_LSTransportHandler, lserror))
        {
#ifdef SECURITY_COMPATIBILITY
            new_transport->msg_handler = _LSMessageMuxHandler;
            new_transport->msg_context = new_transport;

            new_transport->disconnect_handler = _LSDisconnectMuxHandler;
            new_transport->disconnect_context = new_transport;

            new_transport->message_failure_handler = _LSHandleMessageFailureMux;
            new_transport->message_failure_context = new_transport;
#endif //SECURITY_COMPATIBILITY

            sh->transport = new_transport;
        }
        else
        {
            goto error;
        }

        /* Connect to the hub */
        if (!_LSTransportConnect(sh->transport, lserror))
        {
            if (lserror->error_code == LS_ERROR_CODE_CONNECT_FAILURE)
            {
                LOG_LS_ERROR(MSGID_LS_CONN_ERROR, 0, "Failed to connect. Is the hub running?");
            }
            goto error;
        }
    }

    if (sh->transport->is_old_config &&
        !(public_bus ? sh->transport->is_public_allowed : sh->transport->is_private_allowed))
    {
        _LSErrorSet(lserror, MSGID_LS_REQUEST_NAME, LS_ERROR_CODE_PERMISSION, LS_ERROR_TEXT_PERMISSION, name);
        goto error;
    }

    if (!_LSTransportNodeUp(sh->transport, public_bus, lserror))
        goto error;


    if (!_CallMapInit(sh, &sh->callmap, lserror))
    {
        goto error;
    }

    sh->catalog = _CatalogNew(sh);
    if (!sh->catalog)
    {
        LOG_LS_ERROR(MSGID_LS_CATALOG_ERR, 0, "Failed to create new subscription catalog");
        goto error;
    }

    if (!LSRegisterCategory (sh, "/com/palm/luna/private", _privateMethods, NULL, NULL, lserror))
    {
        goto error;
    }

    sh->transport->back_sh[public_bus] = sh;

    if (new_transport && is_name_not_empty)
    {
        pthread_rwlock_wrlock(&transport_map_lock);
        g_hash_table_replace(transport_map,
                             g_strdup(name),
                             sh->transport);
        pthread_rwlock_unlock(&transport_map_lock);
    }

    *ret_sh = sh;

    return true;

error:

    if (sh)
    {
        if (new_transport)
        {
            _LSTransportDisconnect(new_transport, true);
            _LSTransportDeinit(new_transport);
        }
        _CallMapDeinit(sh, sh->callmap);
        _CatalogFree(sh->catalog);

        g_free(sh->name);

        LSHANDLE_SET_DESTROYED(sh, call_ret_addr);

#ifdef MEMCHECK
        LSHANDLE_POISON(sh);
#endif

        g_free(sh);
    }

    *ret_sh = NULL;

    return false;
}

/** @endcond */

/**
 * Return name of luna service handle
 *
 * @param sh In handler
 **/
const char *
LSHandleGetName(LSHandle *sh)
{
    if (!sh) return NULL;
    LSHANDLE_VALIDATE(sh);
    return sh->name;
}

/**
 *******************************************************************************
 * @brief Register a service on the private bus.
 * The old notion of clients and servers does not apply.  Everyone is a
 * service.  Services may make outgoing service calls using LSCall()
 * or handle incomming messages for handlers registered via
 * LSRegisterCategory(), and send replies via LSMessageReply() or
 * LSSubscriptionPost().  A traditional client may register with a NULL name if
 * it never expects to be sent messages.
 *
 * @param name     IN  service name
 * @param *sh      IN  pointer to location where handle to service will be stored
 * @param lserror  OUT set on error
 *
 * @return true on success, otherwise false
 *******************************************************************************
 */
bool
LSRegister(const char *name, LSHandle **sh,
                  LSError *lserror)
{
    return _LSRegisterCommon(name, NULL, sh, false, LSHANDLE_GET_RETURN_ADDR(), lserror);
}

/**
 *******************************************************************************
 * @brief Register a service on the private bus with application Id.
 * For details see LSRegister description.
 *
 * @param name     IN  service name
 * @param app_id   IN  application Id
 * @param *sh      IN  pointer to location where handle to service will be stored
 * @param lserror  OUT set on error
 *
 * @return true on success, otherwise false
 *******************************************************************************
 */
bool
LSRegisterApplicationService(const char *name, const char *app_id, LSHandle **sh,
                  LSError *lserror)
{
    return _LSRegisterCommon(name, app_id, sh, false, LSHANDLE_GET_RETURN_ADDR(), lserror);
}

/** @cond INTERNAL */

static void
DetachHelper(gpointer key, gpointer value, gpointer user_data)
{
    (void)key;
    (void)user_data;
    _LSTransportClientDetach((_LSTransportClient*)value);
}

bool
_LSUnregisterCommon(LSHandle *sh, bool flush_and_send_shutdown, void *call_ret_addr, LSError *lserror)
{
    _LSErrorIfFail(sh != NULL, lserror, MSGID_LS_INVALID_HANDLE);
    LSHANDLE_VALIDATE(sh);

    _LSGlobalLock();

    _LSTransport *transport = sh->transport;
    TRANSPORT_LOCK(&transport->lock);
    g_hash_table_foreach(transport->clients, DetachHelper, NULL);
    TRANSPORT_UNLOCK(&transport->lock);

    if (sh->tableHandlers)
    {
        g_hash_table_unref(sh->tableHandlers);
    }

    _CatalogFree(sh->catalog);

    _CallMapDeinit(sh, sh->callmap);

    sh->transport->back_sh[sh->is_public_bus] = NULL;

    if (!sh->transport->back_sh[1 - sh->is_public_bus])
    {
        if (sh->name && *sh->name)
        {
            pthread_rwlock_wrlock(&transport_map_lock);
            g_hash_table_remove(transport_map, sh->name);
            pthread_rwlock_unlock(&transport_map_lock);
        }
        _LSTransportDisconnect(sh->transport, flush_and_send_shutdown);
        _LSTransportDeinit(sh->transport);
    }

    /* Now we can cleanup the gmainloop connection. */
    if (sh->context)
    {
        g_main_context_unref(sh->context);
        sh->context = NULL;
    }

    g_free(sh->name);

    LSHANDLE_SET_DESTROYED(sh, call_ret_addr);

#ifdef MEMCHECK
    LSHANDLE_POISON(sh);
#endif

    g_free(sh);

    _LSGlobalUnlock();

    return true;
}

/** @endcond */

/**
 *******************************************************************************
 * @brief Unregister a service.
 *
 * @param sh      IN  handle to service
 * @param lserror OUT set on error
 *
 * @return true on success, otherwise false
 *******************************************************************************
 */
bool
LSUnregister(LSHandle *sh, LSError *lserror)
{
    return _LSUnregisterCommon(sh, true, LSHANDLE_GET_RETURN_ADDR(), lserror );
}

/**
 *******************************************************************************
 * @brief Push a role file for this process. Once the role file has been
 * pushed with this function, the process will be restricted to the
 * constraints of the provided role file.
 *
 * @param sh        IN  handle (already connected with LSRegister())
 * @param role_path IN  full path to role file
 * @param lserror   OUT set on error
 *
 * @return true on success, otherwise false
 *******************************************************************************
 */
bool
LSPushRole(LSHandle *sh, const char *role_path, LSError *lserror)
{
    _LSErrorIfFail(sh != NULL, lserror, MSGID_LS_INVALID_HANDLE);

    LSHANDLE_VALIDATE(sh);

    return LSTransportPushRole(sh->transport, role_path, sh->is_public_bus, lserror);
}

/**
 * @} END OF LunaServiceRegistration
 */

/**
 * @addtogroup LunaServiceGlobal
 * @{
 */

static gboolean
_LSIdleCheck(void *_)
{
    if (g_atomic_int_get(&activity_num) != 0)
        return true;

    if (g_atomic_int_compare_and_exchange(&activity, true, false))
        return true;

    idle_callback.cb(idle_callback.data);
    return true;
}

/**
 *******************************************************************************
 * @brief Register a callback that will be called after certain milliseconds of inactivity specified by the timeout parameter.
 *
 * Any stored LSMessage, active subscription (created by LSSubscriptionAdd) or
 * message sent or received is considered as activity. Exception are LSMessage
 * marked as inactive with function LSMessageMarkInactive.
 * This function should be called before any LSRegister call.
 * This requirement is for ease of implementation and not enforced but strongly recommended.
 *
 * @param timeout   IN  time of inactivity (in ms) before callback invocation
 * @param callback  IN  user callback
 * @param userdata  IN  user provided data, that will be passed into callback
 * @param context   IN  context, which will be used to hold timer
 *
 * @code
 * void callBackFunc(void *data) {
 * }
 *
 * LSIdleTimeout(TIMEOUT, callBackFunc, loop, gMainContext);
 * LSRegister("com.name.service", &lsHandle, &error);
 * @endcode
 *
 * @cond INTERNAL
 * Any accept/receive/send generate momentary activity. Transport message
 * create prolongated activity by increasing number of activities. Rationale:
 * stored messages indicate pending activity, like (subscription) reply by
 * user, pending send, unprocessed incoming message, etc.
 *
 * Beside momentary activity, receive and accept also increase number of
 * activities, once we got at least 1 byte of header. Decrement of activities
 * number happen on incomplete receive due to shutdown or when transport
 * message is created. Rationale: sending side can be so slow that time
 * between two recv calls will be bigger then idle timeout. At the same time
 * processing can be so fast, that we need to mark activity in general way.
 * @endcond
 *******************************************************************************
 */
void
LSIdleTimeout(unsigned int timeout, void (*callback)(void*), void *userdata, GMainContext *context)
{
    /* Idle timer source */
    static GSource *s_idle = NULL;

    LS_ASSERT(s_idle == NULL);
    LS_ASSERT(callback != NULL);

    idle_callback.cb = callback;
    idle_callback.data = userdata;

    s_idle = g_timeout_source_new(timeout);
    g_source_set_callback(s_idle, (GSourceFunc)_LSIdleCheck, NULL, NULL);
    g_source_attach(s_idle, context);
    g_source_unref(s_idle);
}

void
LSMessageMarkInactive(LSMessage *message)
{
    LS_ASSERT(message != NULL);
    LS_ASSERT(!message->transport_msg->inactive);

    if (unlikely(message->transport_msg->inactive))
    {
        const char *service_name = LSHandleGetName(LSMessageGetConnection(message));
        const char *category_name = LSMessageGetCategory(message);
        const char *method_name = LSMessageGetMethod(message);
        LOG_LS_ERROR(MSGID_LS_ASSERT, 3,
                     PMLOGKS("MESSAGE_SERVICE", service_name),
                     PMLOGKS("MESSAGE_CATEGORY", category_name),
                     PMLOGKS("MESSAGE_METHOD", method_name),
                     "Message marked as inactive twice");
        /* do nothing */
        return;
    }

    ACTIVITY_DEC(); /* do not treat this message as active */

    /* ensure dtor will not call ACTIVITY_DEC() */
    message->transport_msg->inactive = true;
}

/** @} END OF LunaServiceGlobal */

bool
LSProcessInfoInit(LSProcessInfo *proc_info)
{
    if (proc_info == NULL)
        return false;

    memset(proc_info, 0, sizeof (LSProcessInfo));
    return true;
}
