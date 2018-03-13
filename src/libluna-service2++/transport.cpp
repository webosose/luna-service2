// Copyright (c) 2014-2018 LG Electronics, Inc.
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

#include "transport.hpp"
#include "luna-service2/lunaservice.hpp"
#include "transport.h"


namespace LS {

Transport::Transport(const char *name, const LSTransportHandlers &handlers, const char *app_id)
{
    LS::Error lserror;
    if (!_LSTransportInit(&transportHandle, name, app_id, &handlers, lserror.get()))
        throw lserror;
}

Transport::~Transport()
{
    _LSTransportDisconnect(transportHandle, false);
    _LSTransportDeinit(transportHandle);
}

void Transport::SetLocalListener(const char *name, mode_t mode)
{
    LS::Error lserror;
    if (!_LSTransportSetupListenerLocal(transportHandle, name, mode, lserror.get()))
        throw lserror;
}

} // namespace LS
