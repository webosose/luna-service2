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


#ifndef _TRANSPORT_H_
#define _TRANSPORT_H_

#include <sys/stat.h>
#include <stdbool.h>
#include <pthread.h>
#include <glib.h>
#include <pbnjson.h>

#include <luna-service2/lunaservice.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "error.h"

/** @cond INTERNAL */

typedef struct LSTransport _LSTransport;

#include "payload_internal.h"
#include "transport_message.h"
#include "transport_channel.h"
#include "transport_signal.h"
#include "transport_handlers.h"
#include "transport_serial.h"
#include "transport_outgoing.h"
#include "transport_incoming.h"
#include "transport_client.h"
#include "transport_security.h"
#include "transport_utils.h"

#define STR(X)      #X
#define XSTR(X)     STR(X)

/* Example: to align 32-bit int, align_bytes should be 4 */
static inline unsigned int
PAD_TO_ALIGNMENT(unsigned int align_bytes, unsigned int size_bytes)
{
    /* only works if "align_bytes" is power of two */
    LS_ASSERT((align_bytes & (align_bytes - 1)) == 0);
    return (align_bytes + ((size_bytes - 1) & ~(align_bytes - 1)));
}

/* Don't use this directly; use the PADDING_BYTES_* macros */
static inline unsigned int
_padding_bytes(unsigned int align_bytes, unsigned int size_bytes)
{
    /* only works if ALIGNMENT is power of two */
    LS_ASSERT((align_bytes & (align_bytes - 1)) == 0);
    return (PAD_TO_ALIGNMENT(align_bytes, size_bytes) - size_bytes);
}

#define PADDING_BYTES_VAR(align_var, cur_len) _padding_bytes(sizeof(typeof(align_var)), cur_len)

#define PADDING_BYTES_TYPE(align_type, cur_len) _padding_bytes(sizeof(align_type), cur_len)

/**
 * Used to determine protocol compatibility when registering with the hub.
 * The value is an integer that should be incremented whenever the low level
 * message format changes.
 */
#define LS_TRANSPORT_PROTOCOL_VERSION   1

#define HUB_LOCAL_SOCKET_DIRECTORY      DEFAULT_HUB_LOCAL_SOCKET_DIRECTORY
#define HUB_LOCAL_ADDRESS_NAME          "com.palm.hub"

#define HUB_NAME                        "com.palm.hub"

#define MONITOR_NAME                    "com.webos.monitor"

/*
    Limits the number of times we will send an _LSTransportMessageTypeQueryName message to
    the hub for a dynamic service.
*/
#define MAX_SEND_RETRIES 10

/** Messages larger than 10 MB are dropped */
#define MAX_MESSAGE_SIZE_BYTES  10485760


/** @brief Transport compatibility flags collected during run time
 */
typedef enum LSTransportFlags {
    _LSTransportFlagNoFlags = 0,    /**< Assumed new-style service */
    _LSTransportFlagOldConfig = 1,  /**< Known to have legacy-style configuration */
    _LSTransportFlagPrivateBus = 2, /**< Has private handle */
    _LSTransportFlagPublicBus = 4,  /**< Has public handle */
} _LSTransportFlags;

bool _LSTransportInit(_LSTransport **ret_transport, const char *service_name, const char *app_id, const LSTransportHandlers *handlers, LSError *lserror);
bool _LSTransportDisconnect(_LSTransport *transport, bool flush_and_send_shutdown);
void _LSTransportDeinit(_LSTransport *transport);
void _LSTransportGmainAttach(_LSTransport *transport, GMainContext *context);
GMainContext* _LSTransportGetGmainContext(const _LSTransport *transport);
bool _LSTransportGmainSetPriority(_LSTransport *transport, int priority, LSError *lserror);
bool _LSTransportConnect(_LSTransport *transport, LSError *lserror);
bool _LSTransportAppendCategory(_LSTransport *transport, bool is_public_bus, const char *category, LSMethod *methods, LSError *lserror);
_LSTransportConnectState _LSTransportConnectLocal(const char *unique_name, bool new_socket, int *fd, LSError *lserror);
bool _LSTransportListenLocal(const char *unique_name, mode_t mode, int *fd, LSError *lserror);
bool _LSTransportSetupListenerLocal(_LSTransport *transport, const char *name, mode_t mode, LSError *lserror);
bool _LSTransportSendMessage(_LSTransportMessage *message, _LSTransportClient *client,
                        LSMessageToken *token, LSError *lserror);
void _LSTransportAddInitialWatches(_LSTransport *transport, GMainContext *context);
bool _LSTransportGetPrivileged(const _LSTransport *tansport);
bool _LSTransportGetProxyStatus(const _LSTransport *tansport);

gboolean _LSTransportAcceptConnection(GIOChannel *source, GIOCondition condition, gpointer data);
gboolean _LSTransportReceiveClient(GIOChannel *source, GIOCondition condition, gpointer data);
gboolean _LSTransportSendClient(GIOChannel *source, GIOCondition condition, gpointer data);

bool _LSTransportIsHub(void);

bool LSTransportSend(_LSTransport *transport, const char *origin_exe,
                     const char *origin_id, const char *origin_name,
                     const char *service_name, bool is_public_bus,
                     const char *category, const char *method, const char *payload, const char* applicationId,
                     LSMessageToken *token, LSError *lserror);
bool LSTransportSendMethodToHub(_LSTransport *transport, const char* method, const char* payload,
                               LSMessageToken *token, LSError *lserror);

bool _LSTransportSendReply(const _LSTransportMessage *replyTo, LSPayload *payload, LSError *lserror);
bool _LSTransportSendReplyString(const _LSTransportMessage *replyTo, _LSTransportMessageType type, const char* string, LSError *lserror);

bool LSTransportCancelMethodCall(_LSTransport *transport, const char *service_name, LSMessageToken serial, bool is_public_bus, LSError *lserror);

bool LSTransportPushRole(_LSTransport *transport, const char *path, bool is_public_bus, LSError *lserror);

/* TODO: move these */
bool LSTransportSendMessageMonitorRequest(_LSTransport *transport, LSError *lserror);
bool _LSTransportSendMessageListClients(_LSTransport *transport, LSError *lserror);
bool _LSTransportSendMessageDumpHubData(_LSTransport *transport, LSError *lserror);
bool _LSTransportSendMessageListServiceMethods(_LSTransport *transport, const char *service_name, bool is_public_bus, LSError *lserror);
bool LSTransportSendQueryServiceStatus(_LSTransport *transport, const char *service_name, bool is_public_bus, LSMessageToken *serial, LSError *lserror);
bool LSTransportSendQueryServiceCategory(_LSTransport *transport, bool is_public_bus,
                                         const char *service_name, const char *category,
                                         LSMessageToken *serial, LSError *lserror);

const char* _LSTransportQueryNameReplyGetUniqueName(_LSTransportMessage *message);

bool _LSTransportNodeUp(_LSTransport *transport, bool is_public_bus, LSError *lserror);

bool _LSTransportInitializeSecurityGroups(_LSTransport *transport, const char *map_json, int length);

bool _LSTransportInitializeTrustLevel(_LSTransport *transport, const char * provided_map_json
                        , int provided_map_length,  const char * required_map_json, int required_map_length
                        , const char * trust_as_string, int trust_string_length);

/** @brief Category pattern ACG bitmask
 *
 * When a new category is registered, every method is assigned a bitmask (ACG set) based
 * on matched category patterns.
 */
typedef struct LSTransportCategoryBitmask {
    GPatternSpec *category_pattern;         /**< Category/method pattern */
    LSTransportBitmaskWord *group_bitmask;  /**< ACG bitmask */
    gboolean match_category_only;           /**< Does the pattern match only category? */
} LSTransportCategoryBitmask;

typedef struct LSTransportTrustLevelGroupBitmask {
    GPatternSpec *group_pattern;         /**< Category/method pattern */
    LSTransportBitmaskWord *trustLevel_group_bitmask;  /**< ACG bitmask */
    gboolean match_group_only;           /**< Does the pattern match only category? */
} LSTransportTrustLevelGroupBitmask;

LSTransportCategoryBitmask *LSTransportCategoryBitmaskNew(const char *pattern,
                                                          LSTransportBitmaskWord *bitmask);
LSTransportCategoryBitmask *LSTransportTrustLevelBitmaskNew(const char *pattern,
                                                          LSTransportBitmaskWord *bitmask);

void LSTransportCategoryBitmaskFree(LSTransportCategoryBitmask *v);
void LSTransportTrustLevelGroupBitmaskFree(LSTransportTrustLevelGroupBitmask *v);

size_t LSTransportGetSecurityMaskSize(_LSTransport *transport);
GSList *LSTransportGetCategoryGroups(_LSTransport *transport);
jvalue_ref LSTransportGetGroupsFromMask(_LSTransport *transport, LSTransportBitmaskWord *mask);

jvalue_ref LSTransportGetTrustFromMask(_LSTransport *transport, LSTransportBitmaskWord *mask);
GSList *LSTransportGetTrustLevelToGroups(_LSTransport *transport);

#ifdef LS_TRACK_MESSAGE
jvalue_ref LSTransportGetConnections(_LSTransport *transport);
jvalue_ref LSTransportGetMessages(_LSTransport *transport);

void LSTransportAddMessage(_LSTransport *transport, LSMessage *message);
void LSTransportRemoveMessage(_LSTransport *transport, LSMessage *message);
#endif
size_t LSTransportGetTrustLevelSecurityMaskSize(_LSTransport *transport);
const char* LSTransportGetTrustLevelAsString(_LSTransport *transport);

#ifdef SECURITY_COMPATIBILITY

bool LSTransportIsOldClient(_LSTransport *transport);
bool LSTransportIsPublicAllowed(_LSTransport *transport);
bool LSTransportIsPrivateAllowed(_LSTransport *transport);
bool LSHandleIsOldPublicBus(LSHandle *sh);

/** @brief Reserved compatibility groups private and public
 */
enum {
    SECURITY_PRIVATE_GROUP_BIT = 0,
    SECURITY_PUBLIC_GROUP_BIT = 1,

    SECURITY_RESERVED_BIT_COUNT
};
#endif // SECURITY_COMPATIBILITY

#ifdef __cplusplus
}
#endif

/** @endcond */

#endif // _TRANSPORT_H_
