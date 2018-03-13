// Copyright (c) 2016-2018 LG Electronics, Inc.
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

#include "service.hpp"

#include "error.h"

/** @cond INTERNAL */

/**
 *******************************************************************************
 * @brief Allocate a new service data structure.
 *
 * @param  service_names     IN  array of service names provided
 * @param  num_services      IN  number of services in @p service_names
 * @param  exec_path         IN  path to executable (including args)
 * @param  is_dynamic        IN  true for dynamic service, false for static
 * @param  service_file_path IN  path to service file
 *
 * @retval service on success
 * @retval NULL on failure
 *******************************************************************************
 */
_Service*
_ServiceNew(const char *service_names[], int num_services, const char *exec_path, bool is_dynamic,
            const char *service_file_path)
{
    LS_ASSERT(exec_path != NULL);

    int i = 0;

    _Service *ret = g_new0(_Service, 1);

    ret->service_names = g_new0(char*, num_services);
    ret->num_services = num_services;

    for (i = 0; i < num_services; i++)
    {
        ret->service_names[i] = g_strdup(service_names[i]);
        if (!ret->service_names[i])
        {
            LOG_LS_ERROR(MSGID_LSHUB_SERVICE_ADD_ERR, 0, "Empty service name");
            _ServiceFree(ret);
            return NULL;
        }
    }

    ret->exec_path = g_strdup(exec_path);

    ret->state = _DynamicServiceStateInvalid;
    ret->is_dynamic = is_dynamic;
    ret->service_file_name = g_path_get_basename(service_file_path);

    return ret;
}

/**
 *******************************************************************************
 * @brief Allocate new service data structure with ref count of 1.
 *
 * @param  service_names     IN  array of service names provided
 * @param  num_services      IN  number of services in @p service_names
 * @param  exec_path         IN  path to executable (including args)
 * @param  is_dynamic        IN  true means dynamic service, false means static
 * @param  service_file_path IN  path to service file
 *
 * @retval service on success
 * @retval NULL on failure
 *******************************************************************************
 */
_Service*
_ServiceNewRef(const char *service_names[], int num_services, const char *exec_path,
               bool is_dynamic, const char *service_file_path)
{
    _Service *ret = _ServiceNew(service_names, num_services, exec_path, is_dynamic, service_file_path);
    if (ret)
    {
        ret->ref = 1;
    }
    return ret;
}

/**
 *******************************************************************************
 * @brief Increment ref count for service.
 *
 * @param  service  IN  service
 *******************************************************************************
 */
void
_ServiceRef(_Service *service)
{
    LS_ASSERT(service != NULL);
    LS_ASSERT(g_atomic_int_get(&service->ref) > 0);

    g_atomic_int_inc(&service->ref);
}

/**
 *******************************************************************************
 * @brief Free data structure allocated for service.
 *
 * @param  service  IN  service
 *******************************************************************************
 */
void
_ServiceFree(_Service *service)
{
    LS_ASSERT(service != NULL);
    LS_ASSERT(g_atomic_int_get(&service->ref) == 0);

    if (service->service_names)
    {
        for (int i = 0; i < service->num_services; i++)
        {
            if (service->service_names[i])
            {
                g_free(service->service_names[i]);
            }
        }
        g_free(service->service_names);
    }
    g_free(service->exec_path);
    g_free(service->service_file_name);

#ifdef MEMCHECK
    memset(service, 0xFF, sizeof(_Service));
#endif

    g_free(service);
}

/**
 *******************************************************************************
 * @brief Decrement ref count for service.
 *
 * @param  service  IN  service
 *******************************************************************************
 */
void
_ServiceUnref(_Service *service)
{
    LS_ASSERT(service != NULL);
    LS_ASSERT(g_atomic_int_get(&service->ref) > 0);

    if (g_atomic_int_dec_and_test(&service->ref))
    {
        _ServiceFree(service);
    }
}

void
_ServicePrint(const _Service *service)
{
    if (service)
    {
        LOG_LS_DEBUG("Service_name: \"%s\", exec_path: \"%s\", pid: %d, state: %d, respawn_on_exit: \"%s\"",
                     service->service_names[0], service->exec_path, service->pid, service->state,
                     service->respawn_on_exit ? "true" : "false");
    }
    else
    {
        LOG_LS_DEBUG("Service is NULL in _ServicePrint call");
    }
}

/** @endcond INTERNAL */
