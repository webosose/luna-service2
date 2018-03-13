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

#include <gtest/gtest.h>
#include "luna-service2/lunaservice.hpp"
#include <pbnjson.hpp>

#include "test_util.hpp"

TEST(TestRestricted, Service)
{

    MainLoopT main_loop;

    auto service = LS::registerService("com.webos.service");
    service.attachToLoop(main_loop.get());

    auto echo_callback = [](LSHandle *sh, LSMessage *msg, void *ctxt) -> bool
    {
        LS::Message request(msg);
        request.respond(request.getPayload());
        return true;
    };

    LSMethod methods[] =
    {
        { "private", echo_callback, LUNA_METHOD_FLAGS_NONE },
        { "public", echo_callback, LUNA_METHOD_FLAGS_NONE },
        { nullptr }
    };

    service.registerCategory("/", methods, nullptr, nullptr);

    auto client = LS::registerService("com.webos.client");
    client.attachToLoop(main_loop.get());

    {
        auto c = client.callOneReply("luna://com.webos.service/public", R"({"returnValue": true})").get();
        auto v = pbnjson::JDomParser::fromString(c.getPayload());
        EXPECT_TRUE(v["returnValue"].asBool());
    }

    {
        auto c = client.callOneReply("luna://com.webos.service/private", R"({"returnValue": true})").get();
        auto v = pbnjson::JDomParser::fromString(c.getPayload());
        EXPECT_FALSE(v["returnValue"].asBool());
    }

    // There's a bug in disconnection handling causing crash without manual stop.
    main_loop.stop();
}

TEST(TestRestricted, Application)
{

    MainLoopT main_loop;

    auto service = LS::registerService("com.webos.service");
    service.attachToLoop(main_loop.get());

    auto echo_callback = [](LSHandle *sh, LSMessage *msg, void *ctxt) -> bool
    {
        LS::Message request(msg);
        request.respond(request.getPayload());
        return true;
    };

    LSMethod methods[] =
    {
        { "private", echo_callback, LUNA_METHOD_FLAGS_NONE },
        { "public", echo_callback, LUNA_METHOD_FLAGS_NONE },
        { nullptr }
    };

    service.registerCategory("/", methods, nullptr, nullptr);

    auto client = LS::registerApplicationService("com.webos.application", "com.webos.application");
    client.attachToLoop(main_loop.get());

    {
        auto c = client.callOneReply("luna://com.webos.service/public", R"({"returnValue": true})").get();
        auto v = pbnjson::JDomParser::fromString(c.getPayload());
        EXPECT_TRUE(v["returnValue"].asBool());
    }

    {
        auto c = client.callOneReply("luna://com.webos.service/private", R"({"returnValue": true})").get();
        auto v = pbnjson::JDomParser::fromString(c.getPayload());
        EXPECT_FALSE(v["returnValue"].asBool());
    }

    // There's a bug in disconnection handling causing crash without manual stop.
    main_loop.stop();
}
