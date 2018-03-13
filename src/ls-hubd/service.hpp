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

#ifndef _SERVICE_DESCRIPTION_HPP_
#define _SERVICE_DESCRIPTION_HPP_

#include <glib.h>
#include <memory>

/** @cond INTERNAL */

/**
 *******************************************************************************
 * @brief States of a dynamically launched service
 *******************************************************************************
 */
enum _DynamicServiceState {
    _DynamicServiceStateInvalid = -1,      /**< not a dynamic service */
    _DynamicServiceStateStopped,           /**< not running */
    _DynamicServiceStateSpawned,           /**< spawned, but hasn't registered name
                                                with hub yet */
    _DynamicServiceStateRunning,           /**< name registered with hub and
                                                service was launched manually */
    _DynamicServiceStateRunningDynamic,    /**< name registered with hub and
                                                service was launched dynamically */
};

/**< struct representing a service */
struct _Service {
    int ref;                    /**< ref count */
    char **service_names;       /**< names of services provided (currently only
                                     support one service) */
    int num_services;           /**< number of services provided by executable */
    char *exec_path;            /**< executable path for this service */
    GPid pid;                   /**< pid when running (0 otherwise)  */
    _DynamicServiceState state; /**< see @sa _DynamicServiceState */
    bool respawn_on_exit;       /**< true if we should respawn the service again
                                     when it goes down */
    bool is_dynamic;            /**< true if dynamic; false if static */
    char *service_file_name;    /**< file name of the service file for this service */
};

typedef std::unique_ptr<_Service, void(*)(_Service*)> ServicePtr;

_Service*
_ServiceNew(const char *service_names[], int num_services, const char *exec_path, bool is_dynamic,
            const char *service_file_path);

_Service*
_ServiceNewRef(const char *service_names[], int num_services, const char *exec_path,
               bool is_dynamic, const char *service_file_path);

void
_ServiceRef(_Service *service);

void
_ServiceFree(_Service *service);

void _ServiceUnref(_Service *service);

void
_ServicePrint(const _Service *service);

/** @endcond INTERNAL */

#endif //_SERVICE_DESCRIPTION_HPP_
