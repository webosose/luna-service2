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
#include <vector>

#include "test_util.hpp"

using namespace std;
using namespace LS;

TEST(Signals, Security)
{
    MainLoopT main_loop;

    // Subscribers will help to test publishers
    typedef vector<string> BufferT;
    BufferT payloads;

    struct Sink
    {
        static bool Handle(LSHandle *sh, LSMessage *message, void *ctxt)
        {
            BufferT *received = static_cast<BufferT *>(ctxt);
            received->emplace_back(LSMessageGetPayload(message));
            return true;
        }
    };

    const char *const POSITIVE_RESPONSE = R"({"returnValue":true})";

    // com.webos.client1 is allowed to subscribe for /category1/signal1 only
    auto client1 = registerService("com.webos.client1");
    client1.attachToLoop(main_loop.get());
    auto c1c1 = client1.callSignal("/category1", "signal1", &Sink::Handle, &payloads);
    {
        // We don't want to keep failing tokens. If they're still in the callmap,
        // the signal will be distributed to them by the client code in the callmap
        // as long as there is at least one allowed connection of this client to the hub.
        auto c1c2 = client1.callSignal("/category1", nullptr, &Sink::Handle, &payloads);
        auto c1c3 = client1.callSignal("/category2", nullptr, &Sink::Handle, &payloads);
        usleep(10000);
    }
    ASSERT_EQ(3U, payloads.size());
    ASSERT_EQ(payloads[0], POSITIVE_RESPONSE);
    ASSERT_NE(payloads[1], POSITIVE_RESPONSE);
    ASSERT_NE(payloads[2], POSITIVE_RESPONSE);
    payloads.clear();

    // com.webos.client1 is allowed to subscribe for anything in /category2
    auto client2 = registerService("com.webos.client2");
    client2.attachToLoop(main_loop.get());
    auto c2c1 = client2.callSignal("/category2", nullptr, &Sink::Handle, &payloads);
    {
        auto c2c2 = client2.callSignal("/category1", nullptr, &Sink::Handle, &payloads);
        auto c2c3 = client2.callSignal("/category1/method1", nullptr, &Sink::Handle, &payloads);
        usleep(10000);
    }
    ASSERT_EQ(3U, payloads.size());
    ASSERT_EQ(payloads[0], POSITIVE_RESPONSE);
    ASSERT_NE(payloads[1], POSITIVE_RESPONSE);
    ASSERT_NE(payloads[2], POSITIVE_RESPONSE);
    payloads.clear();

    // com.whatever.client isn't allowed to subscribe for /category1 and /category2
    auto client3 = registerService("com.whatever.client");
    client3.attachToLoop(main_loop.get());
    auto c3c1 = client3.callSignal("/category1", "signal1", &Sink::Handle, &payloads);
    auto c3c2 = client3.callSignal("/category1", nullptr, &Sink::Handle, &payloads);
    auto c3c3 = client3.callSignal("/category2", nullptr, &Sink::Handle, &payloads);
    usleep(10000);
    ASSERT_EQ(3U, payloads.size());
    ASSERT_NE(payloads[0], POSITIVE_RESPONSE);
    ASSERT_NE(payloads[1], POSITIVE_RESPONSE);
    ASSERT_NE(payloads[2], POSITIVE_RESPONSE);
    payloads.clear();


    // Publishers
    static LSSignal signal_table[] = {
        { "signal1", LUNA_SIGNAL_FLAGS_NONE },
        { nullptr }
    };

    // com.webos.service1 is allowed to fire its own signal
    auto service1 = registerService("com.webos.service1");
    service1.registerCategory("/category1", nullptr, signal_table, nullptr);
    service1.registerCategory("/category2", nullptr, signal_table, nullptr);
    service1.attachToLoop(main_loop.get());
    service1.sendSignal("luna://com.webos.service1/category1/signal1", "self");
    usleep(10000);
    ASSERT_EQ(1U, payloads.size());
    EXPECT_EQ(payloads[0], "self"); // received by client1
    payloads.clear();

    // com.webos.service2 is allowed to fire service1's signal
    auto service2 = registerService("com.webos.service2");
    service2.attachToLoop(main_loop.get());
    service2.sendSignal("luna://com.webos.service1/category1/signal1", "service2");
    usleep(10000);
    ASSERT_EQ(1U, payloads.size());
    EXPECT_EQ(payloads[0], "service2");
    payloads.clear();

    service2.sendSignal("luna://com.webos.service1/category2/signal1", "service2");
    usleep(10000);
    ASSERT_EQ(1U, payloads.size());
    EXPECT_EQ(payloads[0], "service2");
    payloads.clear();

    // com.whatever.service isn't allowed to fire anything.
    auto service3 = registerService("com.whatever.service");
    service3.attachToLoop(main_loop.get());
    service3.sendSignal("luna://com.webos.service1/category1/signal1", "whatever");
    usleep(10000);
    ASSERT_EQ(0U, payloads.size());

    main_loop.stop();
}
