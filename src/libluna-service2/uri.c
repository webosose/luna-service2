// Copyright (c) 2015-2018 LG Electronics, Inc.
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

#include "uri.h"

#include <string.h>

#include <glib.h>

#include "error.h"

#define LUNA_PREFIX "luna://"
#define LUNA_OLD_PREFIX "palm://"

#define MAX_NAME_LEN 255

/** @cond INTERNAL */

static inline bool is_valid_initial_char(int c)
{
    switch (c)
    {
    case 'A'...'Z':
    case 'a'...'z':
    case '_':
        return true;
    default:
        return false;
    }
}

static inline bool is_valid_name_char(int c)
{
    switch (c)
    {
    case 'A'...'Z':
    case 'a'...'z':
    case '0'...'9':
    case '_':
        return true;
    default:
        return false;
    }
}

static inline bool is_valid_path_char(int c)
{
    switch (c)
    {
    case 'A'...'Z':
    case 'a'...'z':
    case '0'...'9':
    case '_':
    case '.':
        return true;
    default:
        return false;
    }
}

/**
 *******************************************************************************
 * @brief Validate the service name.
 *
 * @param  service_name
 *
 * @return true if valid, otherwise false
 *******************************************************************************
 */
static bool
_validate_service_name(const char *service_name)
{
    int len;
    const char *p;
    const char *end;
    const char *last_dot;

    len = strlen(service_name);
    p = service_name;
    end = service_name + len;
    last_dot = NULL;

    if (len > MAX_NAME_LEN) return false;
    if (0 == len) return false;

    // unique names are not allowed.
    if (':' == *p) return false;

    if ('.' == *p) return false;

    if (unlikely(!is_valid_initial_char(*p))) return false;

    p++;

    for ( ; p < end; p++)
    {
        if ('.' == *p)
        {
            last_dot = p;

            // skip past '.'
            p++;

            if (p == end) return false;

            // after '.' back to initial character
            if (unlikely(!is_valid_initial_char(*p)))
            {
                return false;
            }
        }
        else if (unlikely(!is_valid_name_char(*p)))
        {
            return false;
        }
    }

    // name must have at least one dot '.'
    if (unlikely(NULL == last_dot)) return false;

    return true;
}


/**
 *******************************************************************************
 * @brief
 *
 * The path has already been validated with the
 * correct characters.  We just need to validate the
 * slash positions.
 *
 * @param  path
 *
 * @retval true if valid, otherwise false
 *******************************************************************************
 */
static bool
_validate_path(const char *path)
{
    int len;
    const char *p;
    const char *last_slash;
    const char *end;

    len = strlen(path);
    p   = path;
    end = path+len;

    if (0 == len)
    {
        return false;
    }

    if ('/' != *p)
    {
        return false;
    }

    last_slash = p;
    p++;

    for (; p < end; p++)
    {
        if ('/' == *p)
        {
            // two successive slashes is invalid.
            if ((p - last_slash) < 2)
                return false;
        }
        else if (unlikely(!is_valid_path_char(*p)))
        {
            return false;
        }
    }

    // trailing '/' is also not allowed.
    if (((end - last_slash) < 2) && len > 1)
    {
        return false;
    }

    return true;
}

/**
 *******************************************************************************
 * @brief Validate method of URI.
 *
 * This assumes that the member has already been validated with the correct
 * characters.
 *
 * @param  method
 *
 * @return true if valid, otherwise false
 *******************************************************************************
 */
static bool
_validate_method(const char *method)
{
    int len;
    const char *p;
    const char *end;

    len = strlen(method);
    p = method;
    end = method+len;

    if (len > MAX_NAME_LEN) return false;
    if (0 == len) return false;

    // first character may not be a digit.
    if (unlikely(!is_valid_initial_char(*p)))
    {
        return false;
    }
    p++;

    for ( ; p < end; p++)
    {
        if (unlikely(!is_valid_name_char(*p)))
        {
            return false;
        }
    }

    return true;
}

/**
 *******************************************************************************
 * @brief Parse a uri and return a _LSUri object containing the individual parts.
 *
 * @param uri
 * @param lserror
 *
 * @retval LSUri, parsed uri
 *******************************************************************************
 */
LSUri *
LSUriParse(const char *uri, LSError *lserror)
{
    LSUri *luri = NULL;
    const char *uri_p;
    const char *first_slash;
    int service_name_len;

    uri_p = uri;

    if (g_str_has_prefix(uri, LUNA_PREFIX))
    {
        uri_p += strlen(LUNA_PREFIX);
    }
    else if (g_str_has_prefix(uri, LUNA_OLD_PREFIX))
    {
        uri_p += strlen(LUNA_OLD_PREFIX);
    }
    else
    {
        _LSErrorSet(lserror, MSGID_LS_INVALID_URI, -EINVAL,
            "%s: Not a valid uri %s - it doesn't begin with " LUNA_PREFIX,
                __FUNCTION__, uri);
        goto error;
    }

    first_slash = strchr(uri_p, '/');
    if (!first_slash)
    {
        _LSErrorSet(lserror, MSGID_LS_INVALID_URI, -EINVAL,
            "%s: Not a valid uri %s", __FUNCTION__, uri);
        goto error;
    }

    luri = g_new0(LSUri, 1);

    service_name_len = first_slash - uri_p;
    luri->serviceName = g_strndup(uri_p, service_name_len);
    uri_p += service_name_len;

    luri->objectPath = g_path_get_dirname(uri_p);
    luri->methodName = g_path_get_basename(uri_p);

    if (!_validate_service_name(luri->serviceName))
    {
        _LSErrorSet(lserror, MSGID_LS_INVALID_URI_SERVICE_NAME, -EINVAL,
                    "%s: Not a valid service name in uri %s (service name: %s)",
                    __FUNCTION__, uri, luri->serviceName);
        goto error;
    }

    if (!_validate_path(luri->objectPath))
    {
        _LSErrorSet(lserror, MSGID_LS_INVALID_URI_PATH, -EINVAL,
                    "%s: Not a valid path in uri %s (path: %s)",
                    __FUNCTION__, uri, luri->objectPath);
        goto error;
    }

    if (!_validate_method(luri->methodName))
    {
        _LSErrorSet(lserror, MSGID_LS_INVALID_URI_METHOD, -EINVAL,
                    "%s: Not a valid method name in uri %s (method: %s)",
                    __FUNCTION__, uri, luri->methodName);
        goto error;
    }

    return luri;
error:
    LSUriFree(luri);

    return NULL;
}


void
LSUriFree(LSUri *luri)
{
    if (NULL == luri) return;

    g_free(luri->serviceName);
    g_free(luri->objectPath);
    g_free(luri->methodName);

#ifdef MEMCHECK
    memset(luri, 0xFF, sizeof(LSUri));
#endif

    g_free(luri);
}

/** @endcond */
