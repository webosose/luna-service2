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

TEST(Old2NewInteraction, OldPublic2New)
{
    auto pub = LS::registerService("com.palm.oldclient.old2new.pub", true);

    MainLoopT mainloop;
    pub.attachToLoop(mainloop.get());

    auto pub_msg = pub.callOneReply("luna://com.palm.newserver.old2new/testCalls/publicCall", "{}").get();
    EXPECT_TRUE(bool(pub_msg));
    EXPECT_FALSE(pub_msg.isHubError());

    auto prv_msg = pub.callOneReply("luna://com.palm.newserver.old2new/testCalls/privateCall", "{}").get();
    EXPECT_TRUE(bool(prv_msg));
    EXPECT_TRUE(prv_msg.isHubError());
}

TEST(Old2NewInteraction, OldPrivate2New)
{
    auto prv = LS::registerService("com.palm.oldclient.old2new.prv", false);

    MainLoopT mainloop;
    prv.attachToLoop(mainloop.get());

    auto prv_msg = prv.callOneReply("luna://com.palm.newserver.old2new/testCalls/privateCall", "{}").get();
    EXPECT_TRUE(bool(prv_msg));
    EXPECT_FALSE(prv_msg.isHubError());

    auto pub_msg = prv.callOneReply("luna://com.palm.newserver.old2new/testCalls/publicCall", "{}").get();
    EXPECT_TRUE(bool(pub_msg));
    EXPECT_TRUE(pub_msg.isHubError());
}

TEST(Old2NewInteraction, OldPublic2NewStatus)
{
    // Check how old service allowed to connect only to public bus able to
    // listen for service status of new services
    auto pub = LS::registerService("com.palm.oldclient.old2new.pub", true);

    auto context = mk_ptr(g_main_context_new(), g_main_context_unref);
    pub.attachToLoop(context.get());

    MainLoop mainloop(context.get());
    bool is_active = false;
    LS::ServerStatusCallback statusCallback = [&is_active, &mainloop](bool isact)
    {
        // keep mainloop running until status changes
        if (is_active != isact)
        {
            is_active = isact;
            mainloop.stop();
        }

        return true;
    };
    auto waitLoopQuit = [&mainloop, &context]() {
        {
            QuitTimeout timeout(1000, mainloop.get());
            mainloop();
            EXPECT_FALSE(timeout.fired());
        } // timeout for old loop terminated here
        mainloop = {context.get()}; // prepare next loop run
    };

    LS::ServerStatus status;
    ASSERT_NO_THROW(status = pub.registerServerStatus("com.palm.newserver.old2new", statusCallback));

    // first response for status
    waitLoopQuit();
    ASSERT_TRUE(is_active);

    pub.callOneReply("luna://com.palm.newserver.old2new/testCalls/restart", "{}", nullptr, nullptr);

    waitLoopQuit();
    EXPECT_FALSE(is_active);

    waitLoopQuit();
    EXPECT_TRUE(is_active);
}

TEST(Old2NewInteraction, OldBoth2NewStatus)
{
    auto context = mk_ptr(g_main_context_new(), g_main_context_unref);

    MainLoop mainloop(context.get());
    bool is_active = false;
    LS::ServerStatusCallback statusCallback = [&is_active, &mainloop](bool isact)
    {
        if (is_active != isact)
        {
            is_active = isact;
            mainloop.stop();
        }

        return true;
    };
    auto waitLoopQuit = [&mainloop, &context]() {
        {
            QuitTimeout timeout(1000, mainloop.get());
            mainloop();
            EXPECT_FALSE(timeout.fired());
        } // timeout for old loop terminated here
        mainloop = {context.get()}; // prepare next loop run
    };

    // Register only public handler for service that is allowed to connect to
    // both buses
    auto pub = LS::registerService("com.palm.oldclient.old2new.both", true);
    pub.attachToLoop(context.get());

    LS::ServerStatus statusPub;
    ASSERT_NO_THROW(statusPub = pub.registerServerStatus("com.palm.newserver.old2new", statusCallback));

    // first response for statusPub
    waitLoopQuit();
    ASSERT_TRUE(is_active);

    pub.callOneReply("luna://com.palm.newserver.old2new/testCalls/restart", "{}", nullptr, nullptr);

    waitLoopQuit();
    EXPECT_FALSE(is_active);

    waitLoopQuit();
    EXPECT_TRUE(is_active);

    // Now register private handler as well and see how it affects behavior
    // Scenario for bug PLAT-22858
    auto prv = LS::registerService("com.palm.oldclient.old2new.both", false);
    prv.attachToLoop(context.get());
    prv.callOneReply("luna://com.palm.newserver.old2new/testCalls/restart", "{}", nullptr, nullptr);

    waitLoopQuit();
    EXPECT_FALSE(is_active);

    waitLoopQuit();
    EXPECT_TRUE(is_active);

    // Now let's see if we can receive service updates on private bus
    statusPub = {}; // stop old ServerStatus running on public bus
    LS::ServerStatus statusPrv;
    EXPECT_NO_THROW(statusPrv = prv.registerServerStatus("com.palm.newserver.old2new", statusCallback));

    // first response for statusPrv
    {
        QuitTimeout timeout(1000, mainloop.get());
        mainloop();
        /* TODO: fix absence of first reply in this situation (bug PLAT-25730)
        EXPECT_FALSE(timeout.fired()) << "First reply with current service status expected (private bus)";
        */
        mainloop = {context.get()};
    }
    EXPECT_TRUE(is_active);

    pub.callOneReply("luna://com.palm.newserver.old2new/testCalls/restart", "{}", nullptr, nullptr);

    waitLoopQuit();
    EXPECT_FALSE(is_active);

    waitLoopQuit();
    EXPECT_TRUE(is_active);

    /* TODO: fix absence of updates in this situation (bug PLAT-25731)
    // Ok. Last try. What if we'll unregister public bus and will leave only private one?
    pub = {};
    prv.callOneReply("luna://com.palm.newserver.old2new/testCalls/restart", "{}", nullptr, nullptr);

    waitLoopQuit();
    EXPECT_FALSE(is_active);

    waitLoopQuit();
    EXPECT_TRUE(is_active);
    */
}

TEST(Old2NewInteraction, OldPrvOfBoth2NewStatus)
{
    // Let's check from the scratch. What will happen when service monitors
    // for status of new service from private bus when it actually have access
    // to both private and public bus?
    auto context = mk_ptr(g_main_context_new(), g_main_context_unref);

    MainLoop mainloop(context.get());
    bool is_active = false;
    LS::ServerStatusCallback statusCallback = [&is_active, &mainloop](bool isact)
    {
        if (is_active != isact)
        {
            is_active = isact;
            mainloop.stop();
        }

        return true;
    };
    auto waitLoopQuit = [&mainloop, &context]() {
        {
            QuitTimeout timeout(1000, mainloop.get());
            mainloop();
            EXPECT_FALSE(timeout.fired());
        } // timeout for old loop terminated here
        mainloop = {context.get()}; // prepare next loop run
    };

    auto prv = LS::registerService("com.palm.oldclient.old2new.both", false);
    prv.attachToLoop(context.get());

    LS::ServerStatus statusPrv;
    ASSERT_NO_THROW(statusPrv = prv.registerServerStatus("com.palm.newserver.old2new", statusCallback));

    waitLoopQuit();
    EXPECT_TRUE(is_active);

    prv.callOneReply("luna://com.palm.newserver.old2new/testCalls/restart", "{}", nullptr, nullptr);

    waitLoopQuit();
    EXPECT_FALSE(is_active);

    waitLoopQuit();
    EXPECT_TRUE(is_active);
}

int main(int argc, char *argv[])
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
