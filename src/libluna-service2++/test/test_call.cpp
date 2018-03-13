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
#include <luna-service2/lunaservice.hpp>

#include "json_payload.hpp"
#include "test_util.hpp"

#include <chrono>
#include <ctime>


namespace
{

#define SIMPLE_URI "luna://com.palm.test_call_service/testCalls/simpleCall"
#define TIMEOUT_URI "luna://com.palm.test_call_service/testCalls/timeoutCall"
#define SUBSCRIBE_URI "luna://com.palm.test_call_service/testCalls/subscribeCall"
#define ECHO_APPID_URI "luna://com.palm.test_call_service/testCalls/echoAppIdCall"

class CallTest : public ::testing::Test
{
protected:

    CallTest():
        _mainloop{nullptr},
        _call{nullptr},
        _resultFlag{NOT_SET}
    {
    }

    virtual void SetUp()
    {
        LS::Error error;
        _mainloop = g_main_loop_new(nullptr, FALSE);
        ASSERT_NE(nullptr, _mainloop);
        ASSERT_NO_THROW(_service = LS::registerService("com.palm.test_call"));
        ASSERT_NO_THROW(_service.attachToLoop(_mainloop));
    }

    virtual void TearDown()
    {
        _service = {};
        g_main_loop_unref(_mainloop);
        // Let hub do its cleanup work before the next test
        usleep(1000);
    }

    GMainLoop * _mainloop;
    LS::Handle _service;
    LS::Call * _call;

    enum ResultFlag
    {
        NOT_SET,
        ON_REPLY,
        ON_TIMEOUT,
        ON_CALL_TIMEOUT,
        ON_MAINLOOP_FAILURE
    };

    ResultFlag _resultFlag;

    static bool onReplyCB(LSHandle * sh, LSMessage * reply, void * context)
    {
        if (reply)
        {
            if (!g_strcmp0(LUNABUS_ERROR_CATEGORY, LSMessageGetCategory(reply)) &&
                !g_strcmp0(LUNABUS_ERROR_CALL_TIMEOUT, LSMessageGetMethod(reply)))
            {
                (static_cast<CallTest *>(context))->_resultFlag = ON_CALL_TIMEOUT;
            }
            else
                (static_cast<CallTest *>(context))->_resultFlag = ON_REPLY;
        }
        g_main_loop_quit((static_cast<CallTest *>(context))->_mainloop);
        return true;
    }

    static gboolean onTimeoutSetCB(gpointer context)
    {
        (static_cast<CallTest *>(context))->_call->continueWith(onReplyCB, context);
        return FALSE;
    }

    static gboolean onTimeoutCallWithCB(gpointer context)
    {
        CallTest * callTest = static_cast<CallTest *>(context);
        *callTest->_call = callTest->_service.callOneReply(SIMPLE_URI, "{}", onReplyCB, context);
        return FALSE;
    }

    static gboolean onHangingCB(gpointer context)
    {
        (static_cast<CallTest *>(context))->_resultFlag = ON_MAINLOOP_FAILURE;
        g_main_loop_quit((static_cast<CallTest *>(context))->_mainloop);
        return FALSE;
    }

    static gboolean onTimeoutCB(gpointer context)
    {
        g_main_loop_quit((static_cast<CallTest *>(context))->_mainloop);
        return FALSE;
    }

};

// Tests LS::Call basic call
TEST_F(CallTest, BasicCall)
{
    LS::Call call;
    ASSERT_NO_THROW(call = _service.callOneReply(SIMPLE_URI, "{}"));
}

// Tests LS::Call throw exception if LSCallXXXX fails
TEST_F(CallTest, ExceptionOnInvalidPayload)
{
    ASSERT_THROW(_service.callOneReply(SIMPLE_URI, ""), LS::Error);
}

// Tests LS::Call throw exception if LSCallXXXX fails
TEST_F(CallTest, ExceptionOnInvalidHandle)
{
    LS::Handle service;
    ASSERT_THROW(service.callOneReply(SIMPLE_URI, "{}"), LS::Error);
}

// Tests set reply callback before main loop
TEST_F(CallTest, SetReplyCBBeforeLoop)
{
    Timeout hangingCB{1000, [this]{return onHangingCB(this);}, _mainloop};
    LS::Call call = _service.callOneReply(SIMPLE_URI, "{}");
    call.continueWith(onReplyCB, this);

    g_main_loop_run(_mainloop);
    ASSERT_FALSE(ON_MAINLOOP_FAILURE == _resultFlag) << "Main loop quit condition failed - loop not finished in time";
    ASSERT_EQ(ON_REPLY, _resultFlag);
    ASSERT_FALSE(call.isActive());
}

// Tests set reply callback after loop
TEST_F(CallTest, SetReplyCBAfterLoop)
{
    Timeout setCB{100, [this]{return onTimeoutSetCB(this);}, _mainloop};
    Timeout hangingCB{1000, [this]{return onHangingCB(this);}, _mainloop};

    LS::Call call = _service.callOneReply(SIMPLE_URI, "{}");
    _call = &call;

    g_main_loop_run(_mainloop);
    ASSERT_FALSE(ON_MAINLOOP_FAILURE == _resultFlag) << "Main loop quit condition failed - loop not finished in time";
    ASSERT_EQ(ON_REPLY, _resultFlag);
}

// Tests calling with callback before main loop started
TEST_F(CallTest, CallCBBeforeLoop)
{
    Timeout hangingCB{1000, [this]{return onHangingCB(this);}, _mainloop};
    LS::Call call = _service.callOneReply(SIMPLE_URI, "{}", onReplyCB, this);

    g_main_loop_run(_mainloop);
    ASSERT_FALSE(ON_MAINLOOP_FAILURE == _resultFlag) << "Main loop quit condition failed - loop not finished in time";
    ASSERT_EQ(ON_REPLY, _resultFlag);
}

// Tests calling with callback after main loop started
TEST_F(CallTest, CallCBAfterLoop)
{
    Timeout hangingCB{1000, [this]{return onHangingCB(this);}, _mainloop};
    Timeout callWithCB{100, [this]{return onTimeoutCallWithCB(this);}, _mainloop};

    LS::Call call;
    _call = &call;

    g_main_loop_run(_mainloop);
    ASSERT_FALSE(ON_MAINLOOP_FAILURE == _resultFlag) << "Main loop quit condition failed - loop not finished in time";
    ASSERT_EQ(ON_REPLY, _resultFlag);
}

// Tests call timeout
TEST_F(CallTest, CallTimeout)
{
    Timeout hangingCB{1000, [this]{return onHangingCB(this);}, _mainloop};

    LS::Call call = _service.callOneReply(TIMEOUT_URI, R"({"timeout": 100})", onReplyCB, this);
    call.setTimeout(200);

    g_main_loop_run(_mainloop);
    ASSERT_FALSE(ON_MAINLOOP_FAILURE == _resultFlag) << "Main loop quit condition failed - loop not finished in time";
    ASSERT_EQ(ON_REPLY, _resultFlag);
}

// Tests call timeout expiration
TEST_F(CallTest, CallTimeoutExpiration)
{
    Timeout hangingCB{1000, [this]{return onHangingCB(this);}, _mainloop};
    Timeout timeoutCB{500, [this]{return onTimeoutCB(this);}, _mainloop};

    LS::Call call = _service.callOneReply(TIMEOUT_URI, R"({"timeout": 300})", onReplyCB, this);
    call.setTimeout(150);

    g_main_loop_run(_mainloop);
    ASSERT_FALSE(ON_MAINLOOP_FAILURE == _resultFlag) << "Main loop quit condition failed - loop not finished in time";
    ASSERT_EQ(ON_CALL_TIMEOUT, _resultFlag);
}

// Tests get interface
TEST_F(CallTest, MainLoopGet)
{
    LS::Call call = _service.callMultiReply(SUBSCRIBE_URI, R"({"subscribe": true, "timeout": 100})");
    auto reply = call.get();
    ASSERT_TRUE(bool(reply));
    reply = call.get();
    ASSERT_TRUE(bool(reply));
}

// Tests isActive method
TEST_F(CallTest, isActive)
{
    LS::Call call = _service.callMultiReply(SUBSCRIBE_URI, R"({"subscribe": true, "timeout": 100})");

    auto reply = call.get();
    ASSERT_TRUE(bool(reply));

    ASSERT_TRUE(call.isActive());
    call.cancel();
    ASSERT_FALSE(call.isActive());

    reply = call.get(200);
    ASSERT_FALSE(bool(reply));
}

// Tests get interface with timeout (wait failed)
TEST_F(CallTest, MainLoopGetTimeoutFail)
{
    LS::Call call = _service.callMultiReply(TIMEOUT_URI, R"({"subscribe": true, "timeout": 300})");
    auto reply = call.get(150);
    ASSERT_FALSE(bool(reply));
    reply = call.get();
    ASSERT_TRUE(bool(reply));
}

// Tests get interface with timeout (wait succeeded)
TEST_F(CallTest, MainLoopGetTimeoutSuccess)
{
    LS::Call call = _service.callMultiReply(TIMEOUT_URI, R"({"subscribe": true, "timeout": 200})");
    auto reply = call.get(250);
    ASSERT_TRUE(bool(reply));
}

// Tests call with/without application Id
TEST_F(CallTest, CallWithApplicationId)
{
    std::string appId = "com.palm.app.foo", noAppId = "", replyAppId;
    LS::Call call = _service.callOneReply(ECHO_APPID_URI, "{}", appId.c_str());
    auto reply = call.get();
    ASSERT_TRUE(bool(reply));
    LS::JSONPayload reply1{reply.getPayload()};
    ASSERT_TRUE(reply1.isValid());
    ASSERT_TRUE(reply1.get("appId", replyAppId));
    ASSERT_EQ(appId, replyAppId);

    call = _service.callOneReply(ECHO_APPID_URI, "{}");
    reply = call.get();
    ASSERT_TRUE(bool(reply));
    LS::JSONPayload reply2{reply.getPayload()};
    ASSERT_TRUE(reply2.isValid());
    ASSERT_TRUE(reply2.get("appId", replyAppId));
    ASSERT_EQ(noAppId, replyAppId);
}

struct CallTimeoutCallbacks
{
    static bool stopOnceCB_LS(LSHandle * sh, LSMessage * reply, void * context)
    {
        g_main_loop_quit(static_cast<GMainLoop *>(context));
        return true;
    }
    static bool stopMultiCB_LS(LSHandle * sh, LSMessage * reply, void * context)
    {
        static int counter{0};
        ++counter;
        if (counter > 1)
        {
            g_main_loop_quit(static_cast<GMainLoop *>(context));
        }
        return true;
    }
    static gboolean stopCB_GLIB(gpointer context)
    {
        g_main_loop_quit(static_cast<GMainLoop *>(context));
        return FALSE;
    }
};

TEST(CallTimeoutTest, BHV_7106_CallTimeoutAfterUnregisterOneReply)
{
    GMainLoop *mainloop = g_main_loop_new(g_main_context_new(), FALSE);
    {
        LS::Handle service;
        ASSERT_NO_THROW(service = LS::registerService("com.palm.test_call"));
        ASSERT_NO_THROW(service.attachToLoop(mainloop));

        LS::Call call = service.callOneReply(TIMEOUT_URI, R"({"timeout": 50})",
            CallTimeoutCallbacks::stopOnceCB_LS, mainloop);
        call.setTimeout(100);
        g_main_loop_run(mainloop);
    }
    GSource *source = g_timeout_source_new(200);
    g_source_set_callback(source, CallTimeoutCallbacks::stopCB_GLIB, mainloop, nullptr);
    g_source_attach(source, g_main_loop_get_context(mainloop));
    g_main_loop_run(mainloop);
    g_main_context_unref(g_main_loop_get_context(mainloop));
    g_main_loop_unref(mainloop);
}

TEST(CallTimeoutTest, BHV_7106_CallTimeoutAfterUnregisterMultiReplyWithCancel)
{
    GMainLoop *mainloop = g_main_loop_new(g_main_context_new(), FALSE);
    {
        LS::Handle service;
        ASSERT_NO_THROW(service = LS::registerService("com.palm.test_call"));
        ASSERT_NO_THROW(service.attachToLoop(mainloop));

        LS::Call call = service.callMultiReply(
            SUBSCRIBE_URI, R"({"subscribe": true, "timeout": 50})", CallTimeoutCallbacks::stopMultiCB_LS, mainloop);
        call.setTimeout(100);
        g_main_loop_run(mainloop);
    }
    GSource *source = g_timeout_source_new(200);
    g_source_set_callback(source, CallTimeoutCallbacks::stopCB_GLIB, mainloop, nullptr);
    g_source_attach(source, g_main_loop_get_context(mainloop));
    g_main_loop_run(mainloop);
    g_main_context_unref(g_main_loop_get_context(mainloop));
    g_main_loop_unref(mainloop);
}

TEST(CallTimeoutTest, BHV_7106_CallTimeoutAfterUnregisterMultiReplyNoCancel)
{
    GMainLoop *mainloop = g_main_loop_new(g_main_context_new(), FALSE);
    {
        LS::Handle service;
        ASSERT_NO_THROW(service = LS::registerService("com.palm.test_call"));
        ASSERT_NO_THROW(service.attachToLoop(mainloop));

        LSMessageToken token;
        LSCall(service.get(), SUBSCRIBE_URI, R"({"subscribe": true, "timeout": 50})",
            CallTimeoutCallbacks::stopMultiCB_LS, mainloop, &token, LS::Error().get());
        LSCallSetTimeout(service.get(), token, 100, LS::Error().get());
        g_main_loop_run(mainloop);
    }
    GSource *source = g_timeout_source_new(200);
    g_source_set_callback(source, CallTimeoutCallbacks::stopCB_GLIB, mainloop, nullptr);
    g_source_attach(source, g_main_loop_get_context(mainloop));
    g_main_loop_run(mainloop);
    g_main_context_unref(g_main_loop_get_context(mainloop));
    g_main_loop_unref(mainloop);
}

}  // anonymous namespace

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

