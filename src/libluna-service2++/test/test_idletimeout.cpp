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

#include <chrono>
#include <thread>

#include <glib.h>
#include <gtest/gtest.h>
#include <luna-service2/lunaservice.hpp>

#include "util.hpp"
#include "json_payload.hpp"
#include "test_util.hpp"

#define TEST_SVC "luna://com.webos.test_service"

#define TIMEOUT (100)
#define MAX_TIME (2*TIMEOUT)

const int call_timeout = 100;

static inline
void checkReply(LS::Call &call, LS::JSONPayload &payload)
{
    LS::Message reply = call.get(call_timeout);
    ASSERT_TRUE(bool(reply));

    payload = LS::JSONPayload(reply.getPayload());
    ASSERT_TRUE(payload.isValid());

    bool returnValue = false;
    ASSERT_TRUE(payload.get("returnValue", returnValue));
    ASSERT_TRUE(returnValue);
}

static inline
void checkReply(LS::Call &call)
{
    LS::JSONPayload payload;
    checkReply(call, payload);
}

class Client
{
private:
    MainLoopT _loop;
public:
    LS::Handle client;

    Client()
    {
        client = LS::registerService();
        client.attachToLoop(_loop.get());
    }

    ~Client()
    {
        // stop serving handle before calling LSUnregister
        _loop.stop();
    }

    void init()
    { ASSERT_EQ(idle(0), 0); }

    int idle(int value = -1)
    {
        LS::JSONPayload data;

        if (value >= 0)
            data.set("set", value);

        LS::JSONPayload answer;
        LS::Call call = client.callOneReply(TEST_SVC "/test/idle", data.getJSONString().c_str());
        checkReply(call, answer);

        int result = -1;
        EXPECT_TRUE(answer.get("idle", result));

        return result;
    }
};

class IdleEnvironment : public ::testing::Environment
{
public:
    virtual void TearDown()
    {
        Client f;
        auto c = f.client.callOneReply(TEST_SVC "/test/stop", "{}");
        c.get();
    }
};

TEST(TestIdleTimeout, SubscriptionCTest)
{
    Client f;
    f.init();

    LS::Call call = f.client.callMultiReply(TEST_SVC "/test/subsc", R"({"subscribe":true})");

    checkReply(call);

    std::this_thread::sleep_for(std::chrono::milliseconds(MAX_TIME*2));
    ASSERT_EQ(f.idle(), 0);

    call = {};

    std::this_thread::sleep_for(std::chrono::milliseconds(MAX_TIME));
    ASSERT_GT(f.idle(), 0);
}

TEST(TestIdleTimeout, SubscriptionCPPTest)
{
    Client f;
    f.init();

    LS::Call call = f.client.callMultiReply(TEST_SVC "/test/subscpp", R"({"subscribe":true})");

    checkReply(call);

    std::this_thread::sleep_for(std::chrono::milliseconds(MAX_TIME*2));
    ASSERT_EQ(f.idle(), 0);

    call = {};

    std::this_thread::sleep_for(std::chrono::milliseconds(MAX_TIME));
    ASSERT_GT(f.idle(), 0);
}

TEST(TestIdleTimeout, InactiveSubscriptionTest)
{
    Client f;
    f.init();

    LS::Call call = f.client.callMultiReply(TEST_SVC "/test/inactive", "{}");

    checkReply(call);

    std::this_thread::sleep_for(std::chrono::milliseconds(MAX_TIME*2));
    ASSERT_GT(f.idle(), 0);
}

TEST(TestIdleTimeout, WakeTest)
{
    Client f;
    f.init();

    for (int i = 0; i < 2*MAX_TIME/TIMEOUT; ++i)
    {
        auto c = f.client.callOneReply(TEST_SVC "/test/ping", "{}");
        checkReply(c);

        std::this_thread::sleep_for(std::chrono::milliseconds(TIMEOUT/2));
    }
    ASSERT_EQ(f.idle(), 0);

    std::this_thread::sleep_for(std::chrono::milliseconds(MAX_TIME));
    ASSERT_GT(f.idle(), 0);
}

TEST(TestIdleTimeout, InvisibleWakeTest)
{
    Client f;
    f.init();

    for (int i = 0; i < 2*MAX_TIME/TIMEOUT; ++i)
    {
        auto c = f.client.callOneReply(TEST_SVC "/com/palm/luna/private/ping", "{}");
        checkReply(c);

        std::this_thread::sleep_for(std::chrono::milliseconds(TIMEOUT/2));
    }
    ASSERT_EQ(f.idle(), 0);

    std::this_thread::sleep_for(std::chrono::milliseconds(MAX_TIME));
    ASSERT_GT(f.idle(), 0);
}

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    ::testing::AddGlobalTestEnvironment(new IdleEnvironment);
    return RUN_ALL_TESTS();
}
