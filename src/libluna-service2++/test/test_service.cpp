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

#include <gtest/gtest.h>

#include <pbnjson.hpp>
#include <luna-service2/lunaservice.hpp>

#include "test_util.hpp"

TEST(TestService, MoveConstructor)
{
    LS::Handle original;

    EXPECT_FALSE(original);
    ASSERT_NO_THROW({ original = LS::registerService("com.webos.service.move"); });
    EXPECT_NO_THROW({ LS::Handle moved { std::move(original) }; });
    EXPECT_FALSE(original);
}

TEST(TestService, MoveOperator)
{
    LS::Handle original;
    LS::Handle moved;

    EXPECT_FALSE(original);
    ASSERT_NO_THROW({ original = LS::registerService("com.webos.service.move"); });
    EXPECT_NO_THROW({ moved = std::move(original); });
    EXPECT_FALSE(original);
    EXPECT_TRUE(bool(moved));
}

TEST(TestService, NotExist)
{
    MainLoopT loop;

    auto client = LS::registerService("com.webos.service.client");
    client.attachToLoop(loop.get());

    auto reply = client.callOneReply("luna://com.webos.service.not_exist/ping", "{}").get();
    ASSERT_TRUE(reply.getPayload());
    EXPECT_TRUE(std::string(reply.getPayload()).find("Service does not exist:") != std::string::npos);

    loop.stop();
}

TEST(TestService, NotRunning)
{
    MainLoopT loop;

    auto client = LS::registerService("com.webos.service.client");
    client.attachToLoop(loop.get());

    auto reply = client.callOneReply("luna://com.webos.service.not_running/ping", "{}").get();
    EXPECT_TRUE(std::string(reply.getPayload()).find("is not running.") != std::string::npos);

    {
        auto callback = [](LSHandle *sh, LSMessage *msg, void*)
        {
            LS::Error error;
            LSMessageReply(sh, msg, R"({"returnValue": true})", error.get());
            return false;
        };

        auto service = LS::registerService("com.webos.service.not_running");
        static LSMethod methods[] = { { "ping", callback }, {} };

        service.registerCategory("/", methods, nullptr, nullptr);
        service.attachToLoop(loop.get());

        reply = client.callOneReply("luna://com.webos.service.not_running/ping", "{}").get();
        ASSERT_TRUE(reply.getPayload());
        EXPECT_EQ(R"({"returnValue": true})", std::string(reply.getPayload()));
    }

    // let the service disconects properly
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    reply = client.callOneReply("luna://com.webos.service.not_running/ping", "{}").get();

    ASSERT_TRUE(reply.getPayload());
    EXPECT_TRUE(std::string(reply.getPayload()).find("is not running.") != std::string::npos);

    loop.stop();
}
