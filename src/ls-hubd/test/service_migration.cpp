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

class EchoService
    : public LS::Handle
{
public:
    explicit EchoService(const char *name)
        : LS::Handle(LS::registerService(name))
    {
        LS_CATEGORY_BEGIN(EchoService, "/test")
            LS_CATEGORY_METHOD(ping)
        LS_CATEGORY_END
    }

private:
    bool ping(LSMessage &message)
    {
        LS::Message request{&message};

        auto reply = JObject{
            {"returnValue", true},
            {"name", this->getName() }
        };
        request.respond(reply.stringify(" ").c_str());
        return true;
    }
};

struct Environment
    : ::testing::Environment
{
    Environment()
    {
        for (auto name : {"com.webos.service.migrated",
                          "com.palm.legacy",
                          "com.lge.legacy",
                          "com.lge.legacy2",
                          "com.palm.service.legacy",
                          "com.palm.service.legacy3"})
        {
            _services.emplace_back(name);
            _services.back().attachToLoop(_main_loop.get());
        }

        _new_client.attachToLoop(_main_loop.get());
        _legacy_client.attachToLoop(_main_loop.get());
    }

    virtual void SetUp()
    {
        _t.reset(new thread{g_main_loop_run, _main_loop.get()});
    }

    virtual void TearDown()
    {
        g_main_loop_quit(_main_loop.get());
        _t->join();
    }

private:
    MainLoopT _main_loop = {g_main_loop_new(NULL, FALSE), g_main_loop_unref};
    unique_ptr<thread> _t;

    list<EchoService> _services;

public:
    LS::Handle _new_client = LS::registerService("com.webos.service.client");
    LS::Handle _legacy_client = LS::registerService("com.palm.legacy_client");
};

Environment *env = static_cast<Environment *>(::testing::AddGlobalTestEnvironment(new Environment));

TEST(Migration, NewClientToMigrated)
{
    auto reply = env->_new_client.callOneReply("luna://com.webos.service.migrated/test/ping", "{}").get();
    auto ref = pbnjson::JValue{{"returnValue", true},
                               {"name", "com.webos.service.migrated"}};
    EXPECT_EQ(JDomParser::fromString(reply.getPayload()), ref);
}

TEST(Migration, LegacyClientToMigrated)
{
    auto reply = env->_legacy_client.callOneReply("luna://com.webos.service.migrated/test/ping", "{}").get();
    auto ref = pbnjson::JValue{{"returnValue", true},
                               {"name", "com.webos.service.migrated"}};
    EXPECT_EQ(JDomParser::fromString(reply.getPayload()), ref);
}

TEST(Migration, NewClientToPalm)
{
    auto reply = env->_new_client.callOneReply("luna://com.palm.legacy/test/ping", "{}").get();
    auto ref = pbnjson::JValue{{"returnValue", true},
                               {"name", "com.palm.legacy"}};
    EXPECT_EQ(JDomParser::fromString(reply.getPayload()), ref);
}

TEST(Migration, LegacyClientToPalm)
{
    auto reply = env->_legacy_client.callOneReply("luna://com.palm.legacy/test/ping", "{}").get();
    auto ref = pbnjson::JValue{{"returnValue", true},
                               {"name", "com.palm.legacy"}};
    EXPECT_EQ(JDomParser::fromString(reply.getPayload()), ref);
}

TEST(Migration, NewClientToPalmSvc)
{
    auto reply = env->_new_client.callOneReply("luna://com.palm.service.legacy/test/ping", "{}").get();
    auto ref = pbnjson::JValue{{"returnValue", true},
                               {"name", "com.palm.service.legacy"}};
    EXPECT_EQ(JDomParser::fromString(reply.getPayload()), ref);
}

TEST(Migration, LegacyClientToPalmSvc)
{
    auto reply = env->_legacy_client.callOneReply("luna://com.palm.service.legacy/test/ping", "{}").get();
    auto ref = pbnjson::JValue{{"returnValue", true},
                               {"name", "com.palm.service.legacy"}};
    EXPECT_EQ(JDomParser::fromString(reply.getPayload()), ref);
}

TEST(Migration, NewClientToLge)
{
    auto reply = env->_new_client.callOneReply("luna://com.lge.legacy/test/ping", "{}").get();
    auto ref = pbnjson::JValue{{"returnValue", true},
                               {"name", "com.lge.legacy"}};
    EXPECT_EQ(JDomParser::fromString(reply.getPayload()), ref);
}

TEST(Migration, LegacyClientToLge)
{
    auto reply = env->_legacy_client.callOneReply("luna://com.lge.legacy/test/ping", "{}").get();
    auto ref = pbnjson::JValue{{"returnValue", true},
                               {"name", "com.lge.legacy"}};
    EXPECT_EQ(JDomParser::fromString(reply.getPayload()), ref);
}

TEST(Migration, NewClientToPalmMigrated)
{
    auto c = env->_new_client.callOneReply("luna://com.palm.migrated/test/ping", "{}");
    auto ref = pbnjson::JValue{{"returnValue", true},
                               {"name", "com.webos.service.migrated"}};
    EXPECT_EQ(JDomParser::fromString(c.get().getPayload()), ref);
}

TEST(Migration, LegacyClientToPalmMigrated)
{
    auto reply = env->_legacy_client.callOneReply("luna://com.palm.migrated/test/ping", "{}").get();
    auto ref = pbnjson::JValue{{"returnValue", true},
                               {"name", "com.webos.service.migrated"}};
    EXPECT_EQ(JDomParser::fromString(reply.getPayload()), ref);
}

TEST(Migration, NewClientToPalmSvcMigrated)
{
    auto c = env->_new_client.callOneReply("luna://com.palm.service.migrated/test/ping", "{}");
    auto ref = pbnjson::JValue{{"returnValue", true},
                               {"name", "com.webos.service.migrated"}};
    EXPECT_EQ(JDomParser::fromString(c.get().getPayload()), ref);
}

TEST(Migration, LegacyClientToPalmSvcMigrated)
{
    auto reply = env->_legacy_client.callOneReply("luna://com.palm.service.migrated/test/ping", "{}").get();
    auto ref = pbnjson::JValue{{"returnValue", true},
                               {"name", "com.webos.service.migrated"}};
    EXPECT_EQ(JDomParser::fromString(reply.getPayload()), ref);
}

TEST(Migration, NewClientToWebosMigrated)
{
    auto reply = env->_new_client.callOneReply("luna://com.lge.migrated/test/ping", "{}").get();
    auto ref = pbnjson::JValue{{"returnValue", true},
                               {"name", "com.webos.service.migrated"}};
    EXPECT_EQ(JDomParser::fromString(reply.getPayload()), ref);
}

TEST(Migration, LegacyClientToWebosMigrated)
{
    auto reply = env->_legacy_client.callOneReply("luna://com.lge.migrated/test/ping", "{}").get();
    auto ref = pbnjson::JValue{{"returnValue", true},
                               {"name", "com.webos.service.migrated"}};
    EXPECT_EQ(JDomParser::fromString(reply.getPayload()), ref);
}

TEST(Migration, NewClientToWebosLegacyPalm)
{
    auto reply = env->_new_client.callOneReply("luna://com.webos.service.legacy/test/ping", "{}").get();
    auto ref = pbnjson::JValue{{"returnValue", true},
                               {"name", "com.palm.legacy"}};
    EXPECT_EQ(JDomParser::fromString(reply.getPayload()), ref);
}

TEST(Migration, LegacyClientToWebosLegacyPalm)
{
    auto reply = env->_legacy_client.callOneReply("luna://com.webos.service.legacy/test/ping", "{}").get();
    auto ref = pbnjson::JValue{{"returnValue", true},
                               {"name", "com.palm.legacy"}};
    EXPECT_EQ(JDomParser::fromString(reply.getPayload()), ref);
}

TEST(Migration, NewClientToWebosLegacyPalmSvc)
{
    auto reply = env->_new_client.callOneReply("luna://com.webos.service.legacy3/test/ping", "{}").get();
    auto ref = pbnjson::JValue{{"returnValue", true},
                               {"name", "com.palm.service.legacy3"}};
    EXPECT_EQ(JDomParser::fromString(reply.getPayload()), ref);
}

TEST(Migration, LegacyClientToWebosLegacyPalmSvc)
{
    auto reply = env->_legacy_client.callOneReply("luna://com.webos.service.legacy3/test/ping", "{}").get();
    auto ref = pbnjson::JValue{{"returnValue", true},
                               {"name", "com.palm.service.legacy3"}};
    EXPECT_EQ(JDomParser::fromString(reply.getPayload()), ref);
}

TEST(Migration, NewClientToWebosLegacyLge)
{
    auto reply = env->_new_client.callOneReply("luna://com.webos.service.legacy2/test/ping", "{}").get();
    auto ref = pbnjson::JValue{{"returnValue", true},
                               {"name", "com.lge.legacy2"}};
    EXPECT_EQ(JDomParser::fromString(reply.getPayload()), ref);
}

TEST(Migration, LegacyClientToWebosLegacyLge)
{
    auto reply = env->_legacy_client.callOneReply("luna://com.webos.service.legacy2/test/ping", "{}").get();
    auto ref = pbnjson::JValue{{"returnValue", true},
                               {"name", "com.lge.legacy2"}};
    EXPECT_EQ(JDomParser::fromString(reply.getPayload()), ref);
}

TEST(Migration, NewClientToLge2)
{
    auto reply = env->_new_client.callOneReply("luna://com.lge.legacy2/test/ping", "{}").get();
    auto ref = pbnjson::JValue{{"returnValue", true},
                               {"name", "com.lge.legacy2"}};
    EXPECT_EQ(JDomParser::fromString(reply.getPayload()), ref);
}

TEST(Migration, LegacyClientToLge2)
{
    auto reply = env->_legacy_client.callOneReply("luna://com.lge.legacy2/test/ping", "{}").get();
    auto ref = pbnjson::JValue{{"returnValue", true},
                               {"name", "com.lge.legacy2"}};
    EXPECT_EQ(JDomParser::fromString(reply.getPayload()), ref);
}
