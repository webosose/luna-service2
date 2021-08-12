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
#ifndef _LUNASERVICE_ERRORS_H_
#define _LUNASERVICE_ERRORS_H_

/**
 * @defgroup LunaServiceErrorCodes Error codes for LSError
 * @ingroup LunaServiceError
 * @{
 */
#define _LS_ERROR_CODE_OFFSET           1024    /**< Try to avoid colliding with errno.h. See _LSErrorSetFromErrno() */

#define LS_ERROR_CODE_UNKNOWN_ERROR          (-1 - _LS_ERROR_CODE_OFFSET)    /**< unknown */
#define LS_ERROR_CODE_OOM                    (-2 - _LS_ERROR_CODE_OFFSET)    /**< out of memory */
#define LS_ERROR_CODE_PERMISSION             (-3 - _LS_ERROR_CODE_OFFSET)    /**< permissions */
#define LS_ERROR_CODE_DUPLICATE_NAME         (-4 - _LS_ERROR_CODE_OFFSET)    /**< duplicate name */
#define LS_ERROR_CODE_CONNECT_FAILURE        (-5 - _LS_ERROR_CODE_OFFSET)    /**< connection failure */
#define LS_ERROR_CODE_DEPRECATED             (-6 - _LS_ERROR_CODE_OFFSET)    /**< API is deprecated */
#define LS_ERROR_CODE_NOT_PRIVILEGED         (-7 - _LS_ERROR_CODE_OFFSET)    /**< service is not privileged */
#define LS_ERROR_CODE_NOT_PROXY_PRIVILEGED   (-8 - _LS_ERROR_CODE_OFFSET)    /**< service is not privileged */
#define LS_ERROR_CODE_PROTOCOL_VERSION       (-9 - _LS_ERROR_CODE_OFFSET)    /**< protocol version mismatch */
#define LS_ERROR_CODE_EAGAIN                 (-10 - _LS_ERROR_CODE_OFFSET)    /**< try again */

/**
 * @} LunaServiceErrorCodes
 */

/** Lunabus service name */
#define LUNABUS_SERVICE_NAME        "com.webos.service.bus"

#define LUNABUS_SERVICE_NAME_REGEX  "^com\\.(palm\\.(luna)?bus|webos\\.service\\.bus)$"

/** Category for lunabus signal addmatch */
#define LUNABUS_SIGNAL_CATEGORY "/com/palm/bus/signal"

#define LUNABUS_SIGNAL_REGISTERED "registered"
#define LUNABUS_SIGNAL_SERVERSTATUS "ServerStatus"
#define LUNABUS_SIGNAL_SERVICE_CATEGORY "ServiceCategory"

/** Category for lunabus errors */
#define LUNABUS_ERROR_CATEGORY "/com/palm/bus/error"

/***
 * Error Method names
 */

/** Sent to callback when method is not handled by service. */
#define LUNABUS_ERROR_UNKNOWN_METHOD "UnknownMethod"

/** Sent to callback when service is down. */
#define LUNABUS_ERROR_SERVICE_DOWN "ServiceDown"

/** Sent to callback when permissions restrict the call from being made */
#define LUNABUS_ERROR_PERMISSION_DENIED "PermissionDenied"

/** Sent to callback when service does not exist (not in service file) */
#define LUNABUS_ERROR_SERVICE_NOT_EXIST "ServiceNotExist"

/** Badly formatted message */
#define LUNABUS_ERROR_BAD_MESSAGE       "BadMessage"

/** Not authorise make proxy calls */
#define LUNABUS_ERROR_NOT_AUTHORISED    "UnAuthorised"

/** Out of memory */
#define LUNABUS_ERROR_OOM "OutOfMemory"

/** Call timeout expired */
#define LUNABUS_ERROR_CALL_TIMEOUT "CallTimeout"

/**
 * UnknownError is usually as:
 * 'UnknownError (some dbus error name we don't handle yet)'
 */
#define LUNABUS_ERROR_UNKNOWN_ERROR "UnknownError"

#endif  /* _LUNASERVICE_ERRORS_H_ */
