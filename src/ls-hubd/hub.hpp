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

#ifndef _HUB_HPP_
#define _HUB_HPP_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "util.hpp"
#include "security.hpp"

struct LSError;
struct _Service;
struct _ClientId;

typedef struct LSError LSError;

bool SetupSignalHandler(int signal, void (*handler)(int));
void LSHubSendConfScanCompleteSignal();

_ClientId* AvailableMapLookup(const char* service_name);
_ClientId* AvailableMapLookupByUniqueName(const char *unique_name);

std::vector<std::string> GetServiceRedirectionVariants(const char* service_name);

#endif  //_HUB_HPP_
