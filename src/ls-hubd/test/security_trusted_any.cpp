// Copyright (c) 2015-2019 LG Electronics, Inc.
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

#include <gtest/gtest.h>
#include "luna-service2++/handle.hpp"

std::unique_ptr<GMainLoop, std::function<void(GMainLoop*)>> mainloop{g_main_loop_new(NULL, FALSE), g_main_loop_unref};

static bool MethodStub(LSHandle *sh, LSMessage *message, void *data)
{
    (void)sh;
    (void)data;

    LSMessageRespond(message, "{}", nullptr);
    g_main_loop_quit(mainloop.get());
    return true;
}

TEST(Trusted, B)
{
    LS::Handle any = LS::registerService("com.service.any");
    any.attachToLoop(mainloop.get());

    static LSMethod methods[] =
    {
        { "anycall", MethodStub, LUNA_METHOD_FLAGS_NONE },
        { nullptr }
    };

    any.registerCategory("/", methods, nullptr, nullptr);
    g_main_loop_run(mainloop.get());
}
