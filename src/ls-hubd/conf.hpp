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

#ifndef _CONF_HPP_
#define _CONF_HPP_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <thread>

#include "watchdog.hpp"

/// @cond INTERNAL
/// @addtogroup LunaServiceHub
/// @{

struct LSError;
typedef struct LSError LSError;

void ConfigSetFilePath(const char *path);
std::thread &ConfigGetParserThread();
void ConfigUpdateSecurity(bool async);
bool ConfigSetupInotify(LSError *lserror);
void ConfigSetDefaults(void);
void ConfigCleanup();

extern int g_conf_watchdog_timeout_sec;
extern LSHubWatchdogFailureMode g_conf_watchdog_failure_mode;
extern int g_conf_query_name_timeout_ms;
extern char* g_conf_dynamic_service_exec_prefix;
extern bool g_conf_security_enabled;
extern bool g_conf_log_service_status;
extern int g_conf_connect_timeout_ms;
extern char* g_conf_monitor_exe_path;
extern char* g_conf_triton_service_exe_path;
extern bool g_conf_allow_null_outbound_by_default;
extern char *g_conf_pid_dir;
extern char *g_conf_devmode_certificate;
extern char *g_conf_default_devmode_certificate;

#ifdef SECURITY_COMPATIBILITY

/// Constants to distinguish the permissions origin
enum BusTypeRoleFlag
{
    NO_BUS_ROLE = 0,        //< New format role file
    PRIVATE_BUS_ROLE = 1,   //< Legacy private role file
    PUBLIC_BUS_ROLE = 2     //< Legacy public role file
};

#endif //SECURITY_COMPATIBILITY

/// @} END OF GROUP LunaServiceHub
/// @endcond

#endif //_CONF_HPP_
