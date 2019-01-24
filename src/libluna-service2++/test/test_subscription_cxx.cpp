// Copyright (c) 2008-2019 LG Electronics, Inc.
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

#include "util.hpp"

#include <glib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>

#include <iostream>
#include <string>
#include <chrono>
#include <thread>
#include <atomic>

#include <gtest/gtest.h>
#include <luna-service2/lunaservice.hpp>

#include "json_payload.hpp"
#include "test_util.hpp"

#define TEST_CLASS_NAME "TestService"
std::atomic_uint g_counter{0};
std::atomic_uint g_sub_count{0};
pthread_barrier_t g_barrier;

class TestService
{
public:
    TestService() : _postId{1}, _mainloop{nullptr}
    {
        _mainloop = g_main_loop_new(nullptr, FALSE);
        _service = LS::registerService("com.palm.test_subscription_service");

        LSMethod methods[] =
        {
            { "stopCall", onStop },
            { "subscribeCall", onRequest },
            { },
        };
        _service.registerCategory("testCalls", methods, nullptr, nullptr);
        _service.setCategoryData("testCalls", this);
        _service.attachToLoop(_mainloop);
        _sp.setServiceHandle(&_service);

        g_sub_count = 0;
        EXPECT_EQ(_sp.getSubscribersCount(), g_sub_count);
    }

    ~TestService()
    {
        g_main_loop_unref(_mainloop);
    }

    bool handleRequest(LSMessage *request)
    {
        if (LSMessageIsSubscription(request))
        {
            LS::Message message{request};
            LS::JSONPayload json;
            json.set("class", TEST_CLASS_NAME);
            json.set("subscribed", _sp.subscribe(message));
            EXPECT_EQ(_sp.getSubscribersCount(), ++g_sub_count);
            json.set("returnValue", true);
            message.respond(json.getJSONString().c_str());
        }
        return true;
    }

    void postUpdate()
    {
        _postId++;
        LS::JSONPayload json;
        json.set("id", _postId);
        _sp.post(json.getJSONString().c_str());
    }

    void run()
    {
        g_timeout_add(100, onPostTimeout, this);
        g_main_loop_run(_mainloop);
    }

    void stop()
    {
        g_timeout_add(100, onStopTimeout, this);
    }

    static bool onStop(LSHandle *sh, LSMessage *request, void *context)
    {
        TestService * ts = static_cast<TestService *>(context);
        ts->stop();
        return true;
    }

    static bool onRequest(LSHandle *sh, LSMessage *request, void *context)
    {
        TestService * ts = static_cast<TestService *>(context);
        ts->handleRequest(request);
        return true;
    }

    static gboolean onPostTimeout(gpointer context)
    {
        TestService * ts = static_cast<TestService *>(context);
        ts->postUpdate();
        return G_SOURCE_CONTINUE;
    }

    static gboolean onStopTimeout(gpointer context)
    {
        TestService * ts = static_cast<TestService *>(context);
        g_main_loop_quit(ts->_mainloop);
        return G_SOURCE_REMOVE;
    }

private:
    int32_t _postId;
    GMainLoop * _mainloop;
    LS::Handle _service;
    LS::SubscriptionPoint _sp;

};

void serviceThreadFunc()
{
    try
    {
        TestService ts;
        ts.run();
    }
    catch (std::exception &e)
    {
        FAIL() << "TestService exception: " << e.what();
    }
    catch (...)
    {
        FAIL();
    }
}

void clientThreadFunc( const char* service_name)
{
    auto context = mk_ptr(g_main_context_new(), g_main_context_unref);
    LS::Handle client = LS::registerService(service_name);
    client.attachToLoop(context.get());

    LS::Call call = client.callMultiReply("luna://com.palm.test_subscription_service/testCalls/subscribeCall",
        R"({"subscribe":true})");
    auto reply = call.get();
    EXPECT_TRUE(bool(reply)) << "No response from test service";
    LS::JSONPayload replyJSON{reply.getPayload()};
    EXPECT_TRUE(replyJSON.isValid());
    bool returnValue = false, isSubscribed = false;
    EXPECT_TRUE(replyJSON.get("returnValue", returnValue));
    EXPECT_TRUE(returnValue);
    EXPECT_TRUE(replyJSON.get("subscribed", isSubscribed));
    EXPECT_TRUE(isSubscribed);
    std::string serviceClass;
    EXPECT_TRUE(replyJSON.get("class", serviceClass));
    EXPECT_EQ(std::string(TEST_CLASS_NAME), serviceClass);

    reply = call.get(200);
    EXPECT_TRUE(bool(reply)) << "No post from test service";
    LS::JSONPayload postJSON{reply.getPayload()};
    EXPECT_TRUE(postJSON.isValid());
    int32_t postId{0};
    EXPECT_TRUE(postJSON.get("id", postId));
    EXPECT_LE(1, postId);
    ++g_counter;

    pthread_barrier_wait(&g_barrier);

    call.cancel();
    --g_sub_count;
}

TEST(TestSubscriptionPoint, SubscriptionDisconnectTest)
{
    std::thread serviceThread{serviceThreadFunc};
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    auto context = mk_ptr(g_main_context_new(), g_main_context_unref);
    {
        LS::Handle client = LS::registerService("service_clientA");
        client.attachToLoop(context.get());

        LS::Call call = client.callMultiReply("luna://com.palm.test_subscription_service/testCalls/subscribeCall",
            R"({"subscribe":true})");

        auto reply = call.get();
        ASSERT_TRUE(bool(reply)) << "No response from test service";
        LS::JSONPayload replyJSON{reply.getPayload()};
        ASSERT_TRUE(replyJSON.isValid());
        bool returnValue = false, isSubscribed = false;
        ASSERT_TRUE(replyJSON.get("returnValue", returnValue));
        ASSERT_TRUE(returnValue);
        ASSERT_TRUE(replyJSON.get("subscribed", isSubscribed));
        ASSERT_TRUE(isSubscribed);
        std::string serviceClass;
        ASSERT_TRUE(replyJSON.get("class", serviceClass));
        ASSERT_EQ(std::string(TEST_CLASS_NAME), serviceClass);

        reply = call.get(800);
        ASSERT_TRUE(bool(reply)) << "No post from test service";
        LS::JSONPayload postJSON{reply.getPayload()};
        ASSERT_TRUE(postJSON.isValid());
        int32_t postId{0};
        ASSERT_TRUE(postJSON.get("id", postId));
        ASSERT_LE(1, postId);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    LS::Handle client = LS::registerService("com.palm.test_subscription_client");
    client.attachToLoop(context.get());

    LS::Call callStop = client.callOneReply("luna://com.palm.test_subscription_service/testCalls/stopCall", "{}");
    callStop.get(200);
    serviceThread.join();

}

TEST(TestSubscriptionPoint, SubscriptionCancelTest)
{
    std::thread serviceThread{serviceThreadFunc};
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    auto context = mk_ptr(g_main_context_new(), g_main_context_unref);
    LS::Handle client = LS::registerService("com.palm.test_subscription_client");
    client.attachToLoop(context.get());

    LS::Call call = client.callMultiReply("luna://com.palm.test_subscription_service/testCalls/subscribeCall",
        R"({"subscribe":true})");

    auto reply = call.get();
    ASSERT_TRUE(bool(reply)) << "No response from test service";
    LS::JSONPayload replyJSON{reply.getPayload()};
    ASSERT_TRUE(replyJSON.isValid());
    bool returnValue = false, isSubscribed = false;
    ASSERT_TRUE(replyJSON.get("returnValue", returnValue));
    ASSERT_TRUE(returnValue);
    ASSERT_TRUE(replyJSON.get("subscribed", isSubscribed));
    ASSERT_TRUE(isSubscribed);
    std::string serviceClass;
    ASSERT_TRUE(replyJSON.get("class", serviceClass));
    ASSERT_EQ(std::string(TEST_CLASS_NAME), serviceClass);

    reply = call.get(200);
    ASSERT_TRUE(bool(reply)) << "No post from test service";
    LS::JSONPayload postJSON{reply.getPayload()};
    ASSERT_TRUE(postJSON.isValid());
    int32_t postId{0};
    ASSERT_TRUE(postJSON.get("id", postId));
    ASSERT_LE(1, postId);

    call.cancel();

    call = client.callOneReply("luna://com.palm.test_subscription_service/testCalls/stopCall", "{}");
    call.get(200);
    serviceThread.join();
}

TEST(TestSubscriptionPoint, SubscriptionTestMultiClientTest)
{
    pthread_barrier_init(&g_barrier, 0, 3);

    std::thread serviceThread{serviceThreadFunc};
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    std::thread client1{clientThreadFunc, "service_clientAA"};
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    std::thread client2{clientThreadFunc, "service_clientBB"};
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    std::thread client3{clientThreadFunc, "service_clientCC"};

    client1.join();
    client2.join();
    client3.join();

    ASSERT_EQ(uint{3}, g_counter);
    GMainLoop * mainloop = g_main_loop_new(nullptr, FALSE);
    LS::Handle client = LS::registerService("com.palm.test_subscription_clientA");
    client.attachToLoop(mainloop);

    client.callOneReply("luna://com.palm.test_subscription_service/testCalls/stopCall", "{}");
    serviceThread.join();
    g_main_loop_unref(mainloop);

    pthread_barrier_destroy(&g_barrier);
}

TEST(TestSubscriptionPoint, PostBeforeSubscribe)
{
    MainLoopT main_loop;

    // Initialize the service with subscription point
    static LSMethod methods[] = {
        { "method",
          [](LSHandle *sh, LSMessage *msg, void *ctx) -> bool
          {
              LS::SubscriptionPoint *s = static_cast<LS::SubscriptionPoint *>(ctx);
              LS::Message req(msg);
              req.respond(R"({"returnValue": true})");
              // We're going to post subscription response to previous clients and then
              // to add this one.
              // Expected that the new client doesn't get the response before it's been
              // subscribed.
              s->post(R"({"status": true})");
              s->subscribe(req);
              return true;
          },
          LUNA_METHOD_FLAGS_NONE },
        {nullptr}
    };
    auto service = LS::registerService("com.webos.service");
    LS::SubscriptionPoint subscr;
    subscr.setServiceHandle(&service);
    service.registerCategory("/", methods, nullptr, nullptr);
    service.setCategoryData("/", &subscr);
    service.attachToLoop(main_loop.get());

    // Run the client
    auto client = LS::registerService("com.webos.client");
    client.attachToLoop(main_loop.get());
    auto call = client.callMultiReply("luna://com.webos.service/method", R"({"subscribe": true})");
    // Get normal response
    auto r = call.get(1000);
    ASSERT_NE(nullptr, r.get());
    EXPECT_STREQ(r.getPayload(), R"({"returnValue": true})");
    // See whether there's a subscription response (there shouldn't be any)
    r = call.get(1000);
    ASSERT_EQ(nullptr, r.get());

    main_loop.stop();
}

TEST(TestSubscriptionPoint, DestroyAfterPost)
{
    MainLoopT main_loop;

    // Initialize the service with subscription point
    static LSMethod methods[] = {
        { "method",
          [](LSHandle *sh, LSMessage *msg, void *ctx) -> bool
          {
              LS::Message req(msg);
              req.respond(R"({"returnValue": true})");

              // Create a temporary subscription point
              LS::SubscriptionPoint subscr;
              subscr.setServiceHandle(static_cast<LS::Handle *>(ctx));

              subscr.subscribe(req);
              subscr.post(R"({"status": true})");
              // Destroy the subscription point. The test will check that the last
              // response was delivered.
              return true;
          },
          LUNA_METHOD_FLAGS_NONE },
        {nullptr}
    };
    auto service = LS::registerService("com.webos.service");
    service.registerCategory("/", methods, nullptr, nullptr);
    service.setCategoryData("/", &service);
    service.attachToLoop(main_loop.get());

    // Run the client
    auto client = LS::registerService("com.webos.client");
    client.attachToLoop(main_loop.get());
    auto call = client.callMultiReply("luna://com.webos.service/method", R"({"subscribe": true})");
    // Get normal response
    auto r = call.get(1000);
    ASSERT_NE(nullptr, r.get());
    EXPECT_STREQ(r.getPayload(), R"({"returnValue": true})");
    // See whether there's a subscription response
    r = call.get(1000);
    ASSERT_NE(nullptr, r.get());
    EXPECT_STREQ(r.getPayload(), R"({"status": true})");
    // Nothing else is expected
    r = call.get(1000);
    ASSERT_EQ(nullptr, r.get());

    main_loop.stop();
}


int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
