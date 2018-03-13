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
#include <luna-service2/lunaservice.hpp>

#include "test_util.hpp"

#include <mutex>
#include <condition_variable>

// Settings service stores message, and adds to the subscription list a bit
// later. The client could disconnect by that time, leaving dangling message.
// Thus, disconnection notification is missed for this particular message.

LS::Message client_message;
std::mutex client_message_mutex;
std::condition_variable client_message_ready;


bool OnServiceTest(LSHandle *sh, LSMessage *msg, void *ctxt)
{
    LS::Message request(msg);
    request.respond(R"({"returnValue": true})");
    client_message = request;
    client_message_ready.notify_one();
    return true;
}

bool OnSubscriptionCancel(LSHandle *sh, LSMessage *reply, void *ctxt)
{
    std::cout << "Subscription cancel" << std::endl;
    return true;
}

TEST(TestSubscriptionCancel, First)
{
    MainLoopT main_loop;

    auto service = LS::registerService("com.webos.service");
    service.attachToLoop(main_loop.get());

    LSMethod methods[] =
    {
        { "test", OnServiceTest, LUNA_METHOD_FLAGS_NONE },
        { nullptr }
    };
    service.registerCategory("/", methods, nullptr, nullptr);
    LSSubscriptionSetCancelFunction(service.get(), OnSubscriptionCancel, nullptr, nullptr);

    {
        // Run a temporary client to capture it's request
        auto client = LS::registerService("com.webos.client");
        client.attachToLoop(main_loop.get());

        auto call = client.callMultiReply("luna://com.webos.service/test", R"({"subscribe": true})");

        std::unique_lock<std::mutex> lock(client_message_mutex);
        client_message_ready.wait(lock);
    }

    // Give the working thread chance to clean up the connection
    usleep(50000);

    ASSERT_FALSE(LSSubscriptionAdd(service.get(), "test_list", client_message.get(), nullptr));
    EXPECT_EQ(0u, LSSubscriptionGetHandleSubscribersCount(service.get(), "test_list"));

    main_loop.stop();
}
