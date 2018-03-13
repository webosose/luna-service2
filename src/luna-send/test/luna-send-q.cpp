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

#include "luna-service2++/handle.hpp"
#include <gtest/gtest.h>
#include <pbnjson.hpp>
#include <sstream>

using namespace std;

typedef unique_ptr<GMainLoop, function<void(GMainLoop*)>> MainLoopT;

struct LunaSend
    : ::testing::Test
{
    LunaSend()
    {
        // First try to use given luna-send from the build directory. Then
        // resort to the system one when testing on target, for instance.
        if (access(luna_send.c_str(), X_OK))
            luna_send = "luna-send";
        std::cout << "Using luna-send: " << luna_send << std::endl;

        static auto method = [](LSHandle *sh, LSMessage *message, void *ctxt) -> bool
        {
            LS::Message request(message);
            request.respond(
                R"({"returnValue": true,
                    "string": "hello",
                    "number": 13,
                    "bool": true
                   })"
                );

            return true;
        };

        static LSMethod methods[] =
        {
            { "method", method, LUNA_METHOD_FLAGS_NONE },
            { nullptr }
        };

        _h = LS::registerService("com.webos.A");
        _h.registerCategory("/test", methods, nullptr, nullptr);
        _h.attachToLoop(_main_loop.get());
    }

    virtual void SetUp()
    {
        _t = thread{g_main_loop_run, _main_loop.get()};
    }

    virtual void TearDown()
    {
        g_main_loop_quit(_main_loop.get());
        _t.join();
    }

protected:
    std::string luna_send = LUNA_SEND;
    MainLoopT _main_loop = {g_main_loop_new(NULL, FALSE), g_main_loop_unref};
    thread _t;
    LS::Handle _h;
};

TEST_F(LunaSend, NotFiltered)
{
    std::string command = luna_send + " -n 1 -m com.webos.B luna://com.webos.A/test/method {}";
    unique_ptr<FILE, function<void(FILE*)>> f{
        popen(command.c_str(), "r"),
        pclose
    };
    ASSERT_TRUE(f.get() != NULL);

    ostringstream oss;
    char buff[512];
    while (fgets(buff, sizeof(buff), f.get()))
        oss << buff;

    auto v = pbnjson::JDomParser::fromString(oss.str());
    ASSERT_TRUE(v.isObject());
    ASSERT_EQ(4, v.objectSize());
    ASSERT_EQ(true, v["returnValue"].asBool());
    ASSERT_EQ(13, v["number"].asNumber<int>());
}

TEST_F(LunaSend, Filtered)
{
    std::string command = luna_send
        + " -n 1 -f"
          " -q returnValue -q number"
          " -m com.webos.B luna://com.webos.A/test/method {}";
    unique_ptr<FILE, function<void(FILE*)>> f{
        popen(command.c_str(), "r"),
        pclose
    };
    ASSERT_TRUE(f.get() != NULL);

    ostringstream oss;
    char buff[512];
    while (fgets(buff, sizeof(buff), f.get()))
        oss << buff;

    auto v = pbnjson::JDomParser::fromString(oss.str());
    ASSERT_TRUE(v.isObject());
    ASSERT_EQ(2, v.objectSize());
    ASSERT_EQ(true, v["returnValue"].asBool());
    ASSERT_EQ(13, v["number"].asNumber<int>());
}
