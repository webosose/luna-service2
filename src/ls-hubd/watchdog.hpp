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

#ifndef _WATCHDOG_HPP_
#define _WATCHDOG_HPP_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

/// @cond INTERNAL
/// @addtogroup LunaServiceHub
/// @{

struct LSError;

typedef struct LSError LSError;

/** Watchdog failure mode */
typedef enum
{
    LSHubWatchdogFailureModeInvalid = -1,   /**< trap */
    LSHubWatchdogFailureModeNoop,           /**< don't do anything */
    LSHubWatchdogFailureModeCrash,          /**< crash */
    LSHubWatchdogFailureModeRdx,            /**< generate rdx report */
} LSHubWatchdogFailureMode;

bool SetupWatchdog(LSError *lserror);
LSHubWatchdogFailureMode LSHubWatchdogProcessFailureMode(const char *mode_str);

/// @} END OF GROUP LunaServiceHub
/// @endcond

#endif  // _WATCHDOG_HPP_
