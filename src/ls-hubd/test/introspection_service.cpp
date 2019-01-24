// Copyright (c) 2016-2019 LG Electronics, Inc.
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

#include "luna-service2/lunaservice.hpp"
#include "test_util.hpp"

MainLoop main_loop;
QuitTimeout quit(2000, main_loop.get());

bool OnQuit(LSHandle *sh, LSMessage *msg, void *ctx)
{
    main_loop.stop();
    return true;
}

LSMethod methods[] = {
    { "quit", OnQuit, LUNA_METHOD_FLAGS_NONE },
    { nullptr }
};

int main()
{
    auto service = LS::registerService("com.webos.service");
    service.attachToLoop(main_loop.get());
    service.registerCategory("/", methods, nullptr, nullptr);

    main_loop();

    return 0;
}
