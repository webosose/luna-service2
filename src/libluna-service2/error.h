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


#ifndef _ERROR_H
#define _ERROR_H

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <luna-service2/lunaservice.h>

#include "log.h"

/**
 * @cond INTERNAL
 * @defgroup LunaServiceErrorInternal   LunaServiceErrorInternal
 * @ingroup LunaServiceInternals
 * @{
 */

#ifdef __cplusplus
extern "C" {
#endif

#define LS_ERROR_TEXT_UNKNOWN_ERROR         "Unknown error"
#define LS_ERROR_TEXT_OOM                   "Out of memory"
#define LS_ERROR_TEXT_PERMISSION            "Invalid permissions for %s"
#define LS_ERROR_TEXT_DUPLICATE_NAME        "Attempted to register for a service name that already exists: %s"
#define LS_ERROR_TEXT_CONNECT_FAILURE       "Unable to connect to %s (%s)"
#define LS_ERROR_TEXT_DEPRECATED            "API is deprecated"
#define LS_ERROR_TEXT_NOT_PRIVILEGED        "LSCallFromApplication with application ID %s but not privileged"
#define LS_ERROR_TEXT_NOT_PROXY_PRIVILEGED  "Called LSCallProxy but service is not proxy/privileged"
#define LS_ERROR_TEXT_PROXY_NULL_PARAMS     "Called LSCallProxy but origin details are NULL"
#define LS_ERROR_TEXT_HUB_CALL_NOT_ALLOWED  "Not allowed to make HUB call as proxy"
#define LS_ERROR_TEXT_PROTOCOL_VERSION      "Protocol version (%d) does not match the hub"
#define LS_ERROR_TEXT_EAGAIN                "Try again later"

inline const char* getBaseFileName_() {
    const char *pch = strrchr("/" __FILE__, '/');
    return (NULL != pch) ? (pch + 1) : __FILE__;
}

#define LS__FILE__BASENAME() ({\
    getBaseFileName_(); \
})


/*
    We don't want the LS_ASSERT macro to evaluate the "cond" expression twice since it may have side-effects.
    But we want to hand some representation of the failing expression to the actual assert macro to allow it
    to log it. So we say assert(!#cond).
*/

#define LS_ASSERT(cond) \
do {                    \
    if (!(cond)) {      \
        LOG_LS_ERROR(MSGID_LS_ASSERT, 4,                  \
                     PMLOGKS("COND", #cond),              \
                     PMLOGKS("FUNC", __FUNCTION__),       \
                     PMLOGKS("FILE" , LS__FILE__BASENAME()),\
                     PMLOGKFV("LINE", "%d", __LINE__),    \
                     "%s: failed", #cond);                \
        assert(!#cond);  \
    }                    \
} while (0)


#define LS_MAGIC(typestring) \
(  ( ((typestring)[sizeof(typestring)*7/8] << 24) | \
     ((typestring)[sizeof(typestring)*6/8] << 16) | \
     ((typestring)[sizeof(typestring)*5/8] << 8)  | \
     ((typestring)[sizeof(typestring)*4/8] ) )    ^ \
   ( ((typestring)[sizeof(typestring)*3/8] << 24) | \
     ((typestring)[sizeof(typestring)*2/8] << 16) | \
     ((typestring)[sizeof(typestring)*1/8] << 8)  | \
     ((typestring)[sizeof(typestring)*0/8] ) ) )

#define LS_MAGIC_SET(object, type)                 \
do {                                               \
    (object)->magic = LS_MAGIC(#type);             \
} while (0)

#define LS_MAGIC_ASSERT(object,type, ...)                    \
do {                                                         \
    if ( (object) && ((object)->magic !=  LS_MAGIC(#type)) ) \
    {                                                        \
        LOG_LS_CRITICAL(MSGID_LS_MAGIC_ASSERT, 0, __VA_ARGS__); \
        LS_ASSERT((object) &&                                \
               ((object)->magic == LS_MAGIC(#type)));        \
    }                                                        \
} while (0)


#define LSERROR_CHECK_MAGIC(lserror)                \
do {                                                \
    LS_MAGIC_ASSERT(lserror, LSError,               \
        "LSError magic value incorrect.  "          \
        "Did you initialize it with LSErrorInit?"); \
} while (0)

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

bool _LSErrorSetFunc(LSError *lserror,
                const char *file, int line, const char *function,
                int error_code, const char *error_message, ...);

bool _LSErrorSetFromErrnoFunc(LSError *lserror,
                         const char *file, int line, const char *function,
                         int error_code);

#define _LSErrorIfFail(cond, lserror, message_id)                     \
do {                                                                  \
    if (unlikely(!(cond)))                                            \
    {                                                                 \
        LOG_LS_ERROR(message_id, 4,                                   \
                     PMLOGKS("COND", #cond),                          \
                     PMLOGKS("FUNC", __FUNCTION__),                   \
                     PMLOGKS("FILE" , LS__FILE__BASENAME()),            \
                     PMLOGKFV("LINE", "%d", __LINE__),                \
                     "%s: failed", #cond);                            \
        _LSErrorSetFunc(lserror, LS__FILE__BASENAME(), __LINE__, __FUNCTION__,\
            -1,                                                       \
            #cond );                                                  \
        return false;                                                 \
    }                                                                 \
} while (0)

#define _LSErrorIfFailMsg(cond, lserror, message_id, error_code, ...) \
do {                                                                  \
    if (unlikely(!(cond)))                                            \
    {                                                                 \
        LOG_LS_ERROR(message_id, 2,                                   \
                     PMLOGKS("COND", #cond),                          \
                     PMLOGKS("FILE", __FILE__),                       \
                     #cond ": failed. " __VA_ARGS__);                 \
                                                                      \
        _LSErrorSetFunc(lserror, LS__FILE__BASENAME(), __LINE__, __FUNCTION__, \
            error_code,                                               \
            #cond ": "                                                \
            __VA_ARGS__);                                             \
        return false;                                                 \
    }                                                                 \
} while (0)

#define _LSErrorGotoIfFail(label, cond, lserror, message_id, error_code, ...) \
do {                                                                  \
    if (unlikely(!(cond)))                                            \
    {                                                                 \
        LOG_LS_ERROR(message_id, 2,                                   \
                     PMLOGKS("COND", #cond),                          \
                     PMLOGKS("FILE", __FILE__),                       \
                     #cond ": failed. " __VA_ARGS__);                 \
                                                                      \
        _LSErrorSetFunc(lserror, LS__FILE__BASENAME(), __LINE__, __FUNCTION__, \
            error_code,                                               \
            #cond ": "                                                \
            __VA_ARGS__);                                             \
        goto label;                                                   \
    }                                                                 \
} while (0)

#define _LSErrorSetNoPrint(lserror, error_code, ...)              \
do {                                                              \
    _LSErrorSetFunc(lserror, LS__FILE__BASENAME(), __LINE__, __FUNCTION__, \
             error_code,                                          \
             __VA_ARGS__);                                        \
} while (0)

#define _LSErrorSetNoPrintLiteral(lserror, error_code, error_message)   \
do {                                                                    \
    _LSErrorSetFunc(lserror, LS__FILE__BASENAME(), __LINE__, __FUNCTION__,\
                    error_code, error_message);                         \
} while (0)

/**
 *******************************************************************************
 * @brief Used to set an error with a printf-style error message.
 *
 * @param  lserror      OUT error
 * @param  message_id   IN  message identifier
 * @param  error_code   IN  error code
 * @param  ...          IN  printf-style format
 *******************************************************************************
 */
#define _LSErrorSet(lserror, message_id, error_code, ...) \
do {                                                      \
    LOG_LS_ERROR(message_id, 2,                           \
                 PMLOGKS("FILE", LS__FILE__BASENAME()),     \
                 PMLOGKFV("LINE", "%d", __LINE__),        \
                 __VA_ARGS__);                            \
    _LSErrorSetNoPrint(lserror, error_code, __VA_ARGS__); \
} while (0)

/**
 *******************************************************************************
 * @brief Use this macro instead of _LSErrorSet to set an error when
 * out of memory.
 *
 * @todo This shouldn't attempt to allocate any memory, since we're already
 * out of memory
 *
 * @param  lserror  IN  ptr to lserror
 *******************************************************************************
 */
#define _LSErrorSetOOM(lserror)                                 \
do {                                                            \
    _LSErrorSet(lserror, MSGID_LS_OOM_ERR, LS_ERROR_CODE_OOM, LS_ERROR_TEXT_OOM); \
} while (0)

/**
 *******************************************************************************
 * @brief Use this macro instead of _LSErrorSet to set an error when
 * retry later error occurs.
 *
 * @param  lserror  IN  ptr to lserror
 *******************************************************************************
 */
#define _LSErrorSetEAgain(lserror)                                 \
do {                                                               \
    _LSErrorSet(lserror, MSGID_LS_EAGAIN_ERR, LS_ERROR_CODE_EAGAIN, LS_ERROR_TEXT_EAGAIN); \
} while (0)

static inline void _LSErrorSetFromGErrorFunc(const char *file,
                                             int line,
                                             LSError *lserror,
                                             const char *message_id,
                                             GError *gerror)
{
    LOG_LS_ERROR(message_id, 4,
                 PMLOGKFV("ERROR_CODE", "%d", gerror->code),
                 PMLOGKS("ERROR", gerror->message),
                 PMLOGKS("FILE", file),
                 PMLOGKFV("LINE", "%d", line),
                 "GLIB Error");
    _LSErrorSetNoPrintLiteral(lserror, gerror->code, gerror->message);
    g_error_free(gerror);
}

/**
 *******************************************************************************
 * @brief Use this macro instead of _LSErrorSet() to set an error from a
 * glib GError. This macro frees the GError.
 *
 * @param  lserror     IN  lserror
 * @param  message_id  IN  message identifier
 * @param  gerror      IN  GError ptr
 *******************************************************************************
 */
#define _LSErrorSetFromGError(lserror, message_id, gerror)             \
    _LSErrorSetFromGErrorFunc(LS__FILE__BASENAME(), __LINE__, lserror, message_id, gerror)


/**
 *******************************************************************************
 * @brief Use this macro instead of _LSErrorSet() to set an error from an
 * errno
 *
 * @param  lserror      IN  lserror
 * @param  message_id   IN  message identifier
 * @param  error_code   IN  errno
 *******************************************************************************
 */
#define _LSErrorSetFromErrno(lserror, message_id, error_code)       \
do {                                                                \
    LOG_LS_ERROR(message_id, 4,                                     \
                 PMLOGKFV("ERROR_CODE", "%d", error_code),          \
                 PMLOGKS("ERROR", g_strerror(error_code)),          \
                 PMLOGKS("FILE", LS__FILE__BASENAME()),               \
                 PMLOGKFV("LINE", "%d", __LINE__),                  \
                 "GLIB Error");                                     \
    _LSErrorSetFromErrnoFunc(lserror, __FILE__, __LINE__,           \
                             __FUNCTION__, error_code);             \
} while (0)

/**
 * @} END OF LunaServiceErrorInternal
 * @endcond
 */

#ifdef __cplusplus
}
#endif

#endif  // _ERROR_H
