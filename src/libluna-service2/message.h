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

#ifndef _MESSAGE_H_
#define _MESSAGE_H_

#include "transport.h"

/**
 * @addtogroup LunaServiceMessage
 * @{
 */

/**
 *******************************************************************************
 * @brief Strucure that will contain information about
 * message.
 *******************************************************************************
 */

struct LSMessage {
    /// refcount
    int          ref;

    /// underlying transport message
    _LSTransportMessage *transport_msg;

    /// connection to bus used by message.
    LSHandle    *sh;

    /// cache of category from message
    const char  *category;

    /// cache of method from message
    const char  *method;
    /// set if method was allocated string
    char  *methodAllocated;

    LSPayload ls_payload;

    /// cache of the payload from message
    const char  *payload;
    /// set if payload was allocated string
    char  *payloadAllocated;

    /// unique token of message
    char  *uniqueTokenAllocated;
    /// kind (cat+method) of message
    char  *kindAllocated;

    ///  @deprecated but left for binary compatibility
    void      *_json_object;

    /// cache of the response token of the message.
    /// For signals, this is the original @ref LSSignalCall() token.
    LSMessageToken responseToken;

    bool         ignore;
    bool         serviceDownMessage;
};

LSMessage *_LSMessageNewRef(_LSTransportMessage *transport_msg, LSHandle *sh);
char *_LSMessageGetKindHelper(const char *category, const char *method);
void _LSMessageParsePayload(LSMessage *message);

bool LSMessageIsConnected(LSMessage *msg);

/**
 * @} END OF LunaServiceMessage
 */

#endif //_MESSAGE_H_

