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

#include "message.hpp"
#include "handle.hpp"

namespace LS
{

void Message::reply(Handle &service_handle, const char *reply_payload)
{
    Error error;

    if (!LSMessageReply(service_handle.get(), _message, reply_payload, error.get()))
    {
        throw error;
    }
}

}
