// Copyright (c) 2008-2018 LG Electronics, Inc.
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

#include "test_util.hpp"

TEST(New2OldInteraction, NewPublic2Old)
{
    auto client = LS::registerService("com.palm.newclient.new2old.public", false);

    MainLoopT mainloop;
    client.attachToLoop(mainloop.get());

    auto bus_msg = client.callOneReply("luna://com.palm.oldserver.new2old/testCalls/getBus", "{}").get();
    EXPECT_TRUE(bool(bus_msg));
    EXPECT_FALSE(bus_msg.isHubError());
    EXPECT_EQ(std::string(R"json({"bus":"public"})json"), std::string(bus_msg.getPayload()));

    auto pub_msg = client.callOneReply("luna://com.palm.oldserver.new2old/testCalls/testPublic", "{}").get();
    EXPECT_TRUE(bool(pub_msg));
    EXPECT_FALSE(pub_msg.isHubError());

    auto prv_msg = client.callOneReply("luna://com.palm.oldserver.new2old/testCalls/testPrivate", "{}").get();
    EXPECT_TRUE(bool(prv_msg));
    EXPECT_TRUE(prv_msg.isHubError());
}

TEST(New2OldInteraction, NewPrivate2Old)
{
    auto client = LS::registerService("com.palm.newclient.new2old.private", false);

    MainLoopT mainloop;
    client.attachToLoop(mainloop.get());

    auto bus_msg = client.callOneReply("luna://com.palm.oldserver.new2old/testCalls/getBus", "{}").get();
    EXPECT_TRUE(bool(bus_msg));
    EXPECT_FALSE(bus_msg.isHubError());
    EXPECT_EQ(std::string(R"json({"bus":"private"})json"), std::string(bus_msg.getPayload()));

    auto pub_msg = client.callOneReply("luna://com.palm.oldserver.new2old/testCalls/testPublic", "{}").get();
    EXPECT_TRUE(bool(pub_msg));
    EXPECT_TRUE(pub_msg.isHubError());

    auto prv_msg = client.callOneReply("luna://com.palm.oldserver.new2old/testCalls/testPrivate", "{}").get();
    EXPECT_TRUE(bool(prv_msg));
    EXPECT_FALSE(prv_msg.isHubError());
}

TEST(New2OldInteraction, NewPubPrv2Old)
{
    auto client = LS::registerService("com.palm.newclient.new2old", false);

    MainLoopT mainloop;
    client.attachToLoop(mainloop.get());

    auto bus_msg = client.callOneReply("luna://com.palm.oldserver.new2old/testCalls/getBus", "{}").get();
    EXPECT_TRUE(bool(bus_msg));
    EXPECT_FALSE(bus_msg.isHubError());
    EXPECT_EQ(std::string(R"json({"bus":"private"})json"), std::string(bus_msg.getPayload()));

    auto pub_msg = client.callOneReply("luna://com.palm.oldserver.new2old/testCalls/testPublic", "{}").get();
    EXPECT_TRUE(bool(pub_msg));
    EXPECT_FALSE(pub_msg.isHubError());

    auto prv_msg = client.callOneReply("luna://com.palm.oldserver.new2old/testCalls/testPrivate", "{}").get();
    EXPECT_TRUE(bool(prv_msg));
    EXPECT_FALSE(prv_msg.isHubError());
}

int main(int argc, char *argv[])
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
