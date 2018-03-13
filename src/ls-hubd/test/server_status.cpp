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

#include <gtest/gtest.h>
#include "luna-service2++/handle.hpp"
#include "test_util.hpp"


TEST(ServerStatus, DownUpDown)
{
    MainLoopT main_loop;

    auto client = LS::registerService("com.webos.client");
    client.attachToLoop(main_loop.get());

    auto call = client.callMultiReply("luna://com.webos.service.bus/signal/registerServerStatus",
                                      R"({"serviceName": "com.webos.service"})");
    auto response = call.get(1000);
    ASSERT_NE(nullptr, response.get());
    auto payload = pbnjson::JDomParser::fromString(response.getPayload());
    ASSERT_EQ(payload["serviceName"].asString(), "com.webos.service");
    EXPECT_FALSE(payload["connected"].asBool());

    response = call.get(1000);
    ASSERT_EQ(nullptr, response.get());

    {
        auto service = LS::registerService("com.webos.service");
        service.attachToLoop(main_loop.get());

        response = call.get(1000);
        ASSERT_NE(nullptr, response.get());
        auto payload = pbnjson::JDomParser::fromString(response.getPayload());
        ASSERT_EQ(payload["serviceName"].asString(), "com.webos.service");
        EXPECT_TRUE(payload["connected"].asBool());

        response = call.get(1000);
        ASSERT_EQ(nullptr, response.get());
    }

    response = call.get(1000);
    ASSERT_NE(nullptr, response.get());
    payload = pbnjson::JDomParser::fromString(response.getPayload());
    ASSERT_EQ(payload["serviceName"].asString(), "com.webos.service");
    EXPECT_FALSE(payload["connected"].asBool());

    response = call.get(1000);
    ASSERT_EQ(nullptr, response.get());

    main_loop.stop();
}

TEST(ServerStatus, UpDown)
{
    MainLoopT main_loop;

    auto service = LS::registerService("com.webos.service");
    service.attachToLoop(main_loop.get());

    auto client = LS::registerService("com.webos.client");
    client.attachToLoop(main_loop.get());
    auto call = client.callMultiReply("luna://com.webos.service.bus/signal/registerServerStatus",
                                      R"({"serviceName": "com.webos.service"})");

    auto response = call.get(1000);
    ASSERT_NE(nullptr, response.get());
    auto payload = pbnjson::JDomParser::fromString(response.getPayload());
    ASSERT_EQ(payload["serviceName"].asString(), "com.webos.service");
    EXPECT_TRUE(payload["connected"].asBool());

    response = call.get(1000);
    ASSERT_EQ(nullptr, response.get());

    service = LS::Handle{};

    response = call.get(1000);
    ASSERT_NE(nullptr, response.get());
    payload = pbnjson::JDomParser::fromString(response.getPayload());
    ASSERT_EQ(payload["serviceName"].asString(), "com.webos.service");
    EXPECT_FALSE(payload["connected"].asBool());

    response = call.get(1000);
    ASSERT_EQ(nullptr, response.get());

    main_loop.stop();
}
