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


#ifndef _TRANSPORT_CLIENT_H_
#define _TRANSPORT_CLIENT_H_

#include "transport_outgoing.h"
#include "transport_incoming.h"
#include "transport_channel.h"
#include "transport_serial.h"
#include "transport_security.h"
#include "transport_utils.h"

/** @cond INTERNAL */

typedef struct LSTransport _LSTransport;

typedef enum LSTransportClientState {
    _LSTransportClientStateInvalid = -1,
    _LSTransportClientStateConnected,       /**< set when we connect */
    _LSTransportClientStateShutdown,        /**< set when we get shutdown message */
    _LSTransportClientStateDisconnected,    /**< disconnected */
} _LSTransportClientState;

/**
 * Because of single connection, client may have no
 * permissions to call the counterparty. This flag
 * should be sent to the both peers. Sender shouldn't make
 * calls if is not allowed, and reciever shouldn't reply on
 * calls if client has no inbound permissions.
 */
typedef enum  {
    _LSClientAllowInbound = 1,
    _LSClientAllowOutbound = 2,
    _LSClientAllowBoth = _LSClientAllowInbound | _LSClientAllowOutbound,
} _LSTransportClientPermissions;

/**
 * A "client" encapsulates a connection to someone that you want to
 * communicate with. In the Luna Service world, the name is a bit misleading
 * because a client can serve as a LS client or LS server (i.e., it can
 * make method calls, process them, or do both).
 *
 * A LSTransportClient is created for each connection, including the hub,
 * monitor, and anyone else that you might be connecting to. It contains
 * incoming and outgoing buffers that keep track of data that is being
 * sent and received to/from the client.
 */
struct LSTransportClient {
    int ref;                            /**< ref count */
    char *unique_name;                  /**< globally unique address */
    char *service_name;                 /**< well-known name (e.g., com.palm.foo) */
    char *app_id;                       /**< application id for non-native applications */
    char *exe_path;                     /**<exe_path */
    _LSTransportClientState state;      /* TODO: locking? */
    _LSTransport *transport;            /**< ptr back to overall transport obj */
    _LSTransportChannel channel;
    _LSTransportCred *cred;             /**< security credentials */
    _LSTransportOutgoing *outgoing;
    _LSTransportIncoming *incoming;
    bool is_dynamic;                    /**< true for a dynamic service */
    LSTransportBitmaskWord *security_required_groups; /**< bitmask (see security_mask_size in struct LSTransport) */
    _LSTransportClientPermissions permissions;
    LSTransportBitmaskWord *required_trust_level;  /**< bitmask (see security_mask_size in struct LSTransport) */
    char *trust_level_string;                      /** < trust level as string */
    //TBD: We still need trust level here?
};

_LSTransportClient* _LSTransportClientNew(_LSTransport* transport, int fd, const char *service_name, const char *unique_name, _LSTransportOutgoing *outgoing);
void _LSTransportClientFree(_LSTransportClient* client);
_LSTransportClient* _LSTransportClientNewRef(_LSTransport* transport, int fd, const char *service_name, const char *unique_name, _LSTransportOutgoing *outgoing);
void _LSTransportClientRef(_LSTransportClient *client);
void _LSTransportClientUnref(_LSTransportClient *client);
void _LSTransportClientDetach(_LSTransportClient *client);
const char* _LSTransportClientGetUniqueName(const _LSTransportClient *client);
void _LSTransportClientSetUniqueName(_LSTransportClient *client, char *unique_name);
const char* _LSTransportClientGetApplicationId(const _LSTransportClient *client);
void _LSTransportClientSetApplicationId(_LSTransportClient *client, const char *app_id);
const char* _LSTransportClientGetServiceName(const _LSTransportClient *client);
const char*  _LSTransportClientGetTrustString(const _LSTransportClient *client);
const char* _LSTransportClientGetTrust(const _LSTransportClient *client);
const char* _LSTransportClientGetExePath(const _LSTransportClient *client);
const char* _LSTransportClientTrustLevel(const _LSTransportClient *client);
pid_t _LSTransportClientGetPid(const _LSTransportClient *client);
uid_t _LSTransportClientGetUid(const _LSTransportClient *client);
gid_t _LSTransportClientGetGid(const _LSTransportClient *client);
_LSTransportChannel* _LSTransportClientGetChannel(_LSTransportClient *client);
_LSTransport* _LSTransportClientGetTransport(const _LSTransportClient *client);
const _LSTransportCred* _LSTransportClientGetCred(const _LSTransportClient *client);
bool _LSTransportClientAllowInboundCalls(const _LSTransportClient *client);
bool _LSTransportClientAllowOutboundCalls(const _LSTransportClient *client);
void _LSTransportClientSetTrustString(_LSTransportClient *client, const char *trust);
// Requires groups initialization. json - array of strings. a string - security group
// Ex.: ["camera", "torch"]
bool _LSTransportClientInitializeSecurityGroups(_LSTransportClient *client, const char *groups_json);

// Requires groups initialization. json - array of strings. a string - security group
// Ex.: ["camera", "torch"]
bool _LSTransportClientInitializeTrustLevel(_LSTransportClient *client, const char *trust_level);
bool _LSTransportClientSetExePath(_LSTransportClient *client, const char *exe_path);
/** @endcond */

#endif      // _TRANSPORT_CLIENT_H_
