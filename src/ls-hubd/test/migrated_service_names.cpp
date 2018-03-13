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

#include <luna-service2/lunaservice.hpp>
#include <gtest/gtest.h>
#include <pbnjson.hpp>
#include <list>

using namespace std;
using namespace pbnjson;

typedef unique_ptr<GMainLoop, void (*)(GMainLoop*)> MainLoopT;

class ClientService: public LS::Handle
{
public:
    ClientService(): LS::Handle(LS::registerService("com.webos.service.client"))
    {
        LS_CATEGORY_BEGIN(ClientService, "/test")
            LS_CATEGORY_METHOD(callback)
        LS_CATEGORY_END
    }

    string &senderServiceName() { return last_echo_service; }

    LS::Call callOneReply(const char *uri, const char *payload, const char *appID = NULL)
    {
        last_echo_service = "";
        return LS::Handle::callOneReply(uri, payload, appID);
    }

private:
    bool callback(LSMessage &message)
    {
        LS::Message request{&message};

        last_echo_service = request.getSenderServiceName();
        request.respond("{}");

        return true;
    }

    string last_echo_service;
};

class EchoService : public LS::Handle
{
public:
    EchoService(): LS::Handle(LS::registerService("com.webos.service.echo_service"))
    {
        LS_CATEGORY_BEGIN(EchoService, "/test")
            LS_CATEGORY_METHOD(ping)
        LS_CATEGORY_END
    }

private:
    bool ping(LSMessage &message)
    {
        LS::Message request{&message};

        auto call = callOneReply("luna://com.webos.service.client/test/callback", "{}");
        call.get(100);

        request.respond("{}");
        return true;
    }
};

struct Environment
    : ::testing::Environment
{
    Environment(): _service(), _client()
    {
        _service.attachToLoop(_main_loop.get());
        _client.attachToLoop(_main_loop.get());
    }

    virtual void SetUp()
    {
        _t.reset(new thread{g_main_loop_run, _main_loop.get()});
    }

    virtual void TearDown()
    {
        _client.senderServiceName().clear();

        g_main_loop_quit(_main_loop.get());
        _t->join();
    }

private:
    MainLoopT _main_loop = {g_main_loop_new(NULL, FALSE), g_main_loop_unref};
    unique_ptr<thread> _t;
    EchoService _service;

public:
    ClientService _client;
};

Environment *env = static_cast<Environment *>(::testing::AddGlobalTestEnvironment(new Environment));

TEST(Migration, Migrated)
{
    auto c = env->_client.callOneReply("luna://com.webos.service.echo_service/test/ping", "{}");
    EXPECT_TRUE((bool)c.get(300));
    EXPECT_STREQ(env->_client.senderServiceName().c_str(), "com.webos.service.echo_service");
}

TEST(Migration, PalmMigrated)
{
    auto c = env->_client.callOneReply("luna://com.palm.echo_service/test/ping", "{}");
    EXPECT_TRUE((bool)c.get(300));
    EXPECT_STREQ(env->_client.senderServiceName().c_str(), "com.webos.service.echo_service");
}

//FIXME: This has been an invalid test case. It should be removed or fixed later.
//       And Call::get(msTime) does not work as intended. This also should be fixed later.
TEST(Migration, WebosMigrated)
{
    auto c = env->_client.callOneReply("luna://com.webos.echo_service/test/ping", "{}");
    EXPECT_TRUE((bool)c.get(300));
    EXPECT_STREQ(env->_client.senderServiceName().c_str(), "com.webos.service.echo_service");
}
