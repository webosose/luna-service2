// Copyright (c) 2014-2019 LG Electronics, Inc.
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

#define private public
#include <pbnjson.hpp>
#undef private

#include "luna-service2/lunaservice.hpp"
#include "luna-service2/lunaservice-meta.h"

#include <gtest/gtest.h>
#include "test_util.hpp"

using namespace std;
using pbnjson::JValue;
using pbnjson::JSchemaFragment;

class TestCategory
    : public ::testing::Test
{
protected:
    LS::Handle sh, sh_client;
    GMainLoop *main_loop;

private:
    bool done; // still waiting

    virtual void SetUp()
    {
        done = false;
        ping = [&](LSMessage *) { finish(); return false; };
        pong = [&](LSMessage *) { finish(); return false; };

        main_loop = g_main_loop_new(nullptr, false);

        ASSERT_NO_THROW({ sh = LS::registerService("com.palm.test"); });
        ASSERT_NO_THROW({ sh.attachToLoop(main_loop); });

        ASSERT_NO_THROW({ sh_client = LS::registerService("com.palm.client1"); });
        ASSERT_NO_THROW({ sh_client.attachToLoop(main_loop); });
    }

    virtual void TearDown()
    {
        ASSERT_NO_THROW({ sh = LS::Handle(); });
        ASSERT_NO_THROW({ sh_client = LS::Handle(); });
        g_main_loop_unref(main_loop);
    }

protected:
    function<bool(LSMessage *message)> ping, pong;

    template<bool (TestCategory::*M)(LSMessage&)>
    static constexpr LSFilterFunc wrap()
    { return &LS::Handle::methodWraper<TestCategory, M>; }

    void finish(bool done = true)
    { this->done = done; }

    void wait()
    {
        auto ctx = g_main_loop_get_context(main_loop);

        while (!done)
        { (void) g_main_context_iteration(ctx, true); }
        finish(false);
    }

    // specially for LS_CATEGORY_END forward registerCategory and
    // setCategoryData
    template <typename... Args>
    void registerCategory(Args &&... args)
    { sh.registerCategory(std::forward<Args>(args)...); }

    template <typename... Args>
    void setCategoryData(Args &&... args)
    { sh.setCategoryData(std::forward<Args>(args)...); }

public:
    void reg()
    {
        LS_CATEGORY_BEGIN("/")
            LS_CATEGORY_METHOD(cbPing)
        LS_CATEGORY_END
    }

    bool cbPing(LSMessage &message) { return ping(&message); }
    bool cbPong(LSMessage &message) { return pong(&message); }
};

TEST_F(TestCategory, DummyRegister)
{
    ASSERT_NO_THROW({ sh.registerCategory("/", nullptr, nullptr, nullptr); });
}

TEST_F(TestCategory, UnregisteredSet)
{
    EXPECT_THROW({ sh.setCategoryData("/", this); }, LS::Error);
    EXPECT_THROW({ sh.setCategoryDescription("/", jnull()); }, LS::Error);
}

TEST_F(TestCategory, SetDescription)
{
    auto description = JValue
    {
        { "methods", {
            { "ping", {
                { "call", {
                    { "type", "object" },
                    { "description", "simple ping" },
                    { "additionalProperties", false },
                }},
            }},
        }},
    };

    ASSERT_NO_THROW({ sh.registerCategory("/", nullptr, nullptr, nullptr); });
    EXPECT_NO_THROW({ sh.setCategoryDescription("/", description.m_jval); });

    // Actually we should to check that effect of prev setting disappeared
    // without any leaks. But at least we'll test that it doesn't fall.
    auto description2 = JValue
    {
        { "methods", {
            { "ping", {
                { "call", {
                    { "type", "object" },
                    { "description", "simple ping" },
                    { "additionalProperties", false },
                }},
            }},
            { "pong", {
                { "call", {
                    { "type", "object" },
                    { "description", "simple ping" },
                    { "additionalProperties", false },
                }},
            }},
        }},
    };
    EXPECT_NO_THROW({ sh.setCategoryDescription("/", description2.m_jval); });
}

TEST_F(TestCategory, ValidationWithRef)
{
    auto description = JValue
    {
        { "definitions", {
            { "foo", {
                { "type", "object" },
                { "description", "simple ping" },
                { "additionalProperties", false },
            }},
        }},
        { "methods", {
            { "ping", {
                { "call", {
                    { "$ref", "#/definitions/foo" }
                }},
            }},
        }},
    };

    LSMethod methods[] = {
        { "ping", wrap<&TestCategory::cbPing>(), LUNA_METHOD_FLAG_VALIDATE_IN },
        { nullptr, nullptr },
    };

    ASSERT_NO_THROW({ sh.registerCategory("/", methods, nullptr, nullptr); });
    ASSERT_NO_THROW({ sh.setCategoryData("/", this); });
    EXPECT_NO_THROW({ sh.setCategoryDescription("/", description.m_jval); });

    bool havePing = false;
    ping = [&](LSMessage *m) {
        finish();
        havePing = true;
        LS::Error e;
        EXPECT_TRUE(LSMessageRespond(m, "{\"returnValue\":true, \"answer\":42}", e.get())) << e.what();
        return true;
    };

    LS::Call call;
    LS::Message reply;
    JValue response;

    {
        SCOPED_TRACE("test against wrong param");
        ASSERT_NO_THROW({ call = sh.callOneReply("luna://com.palm.test/ping", "{\"abc\":3}"); });
        ASSERT_NO_THROW({ reply = call.get(1000); });
        EXPECT_FALSE(havePing);
        EXPECT_TRUE(bool(reply));

        if (reply)
        {
            response = pbnjson::JDomParser::fromString(reply.getPayload());
            EXPECT_EQ(JValue(false), response["returnValue"])
                << "Actual response: " << ::testing::PrintToString(response);
        }
    }

    {
        SCOPED_TRACE("test against correct param");
        ASSERT_NO_THROW({ call = sh.callOneReply("luna://com.palm.test/ping", "{}"); });
        reply = {};
        ASSERT_NO_THROW({ reply = call.get(1000); });
        EXPECT_TRUE(bool(reply));
        EXPECT_TRUE(havePing);

        if (reply)
        {
            response = pbnjson::JDomParser::fromString(reply.getPayload());
            auto expected_answer = JValue
            {
                { "returnValue", true },
                { "answer", 42 },
            };
            EXPECT_EQ(expected_answer, response);
        }
    }
}

TEST_F(TestCategory, TestUserData)
{
    const char *category_context  = "CATEGORY_CONTEXT";
    const char *method_context  = "METHOD_CONTEXT";

    auto cb = [](LSHandle *sh, LSMessage *m, void *ctxt)
    {
        EXPECT_STREQ((const char *)ctxt, "CATEGORY_CONTEXT");

        LS::Error e;
        EXPECT_TRUE(LSMessageRespond(m, "{\"returnValue\":true, \"answer\":42}", e.get())) << e.what();
        return true;
    };

    auto mcb = [](LSHandle *sh, LSMessage *m, void *ctxt)
    {
        EXPECT_STREQ((const char *)ctxt, "METHOD_CONTEXT");

        LS::Error e;
        EXPECT_TRUE(LSMessageRespond(m, "{\"returnValue\":true, \"answer\":42}", e.get())) << e.what();
        return true;
    };

    LSMethod methods[] = {
        { "ping_1", cb },
        { "ping_2", cb },
        { "ping_3", mcb },
        { nullptr, nullptr },
    };

    ASSERT_NO_THROW({ sh.registerCategory("/", methods, nullptr, nullptr); });
    ASSERT_NO_THROW({ sh.setCategoryData("/", (void *)category_context); });
    ASSERT_NO_THROW({ sh.setMethodData("/", "ping_3", (void *)method_context); });

    LS::Error e;

    auto call = sh_client.callOneReply("luna://com.palm.test/ping_1", "'{}'");
    call.get();

    call = sh_client.callOneReply("luna://com.palm.test/ping_2", "'{}'");
    call.get();

    call = sh_client.callOneReply("luna://com.palm.test/ping_3", "'{}'");
    call.get();
}

TEST_F(TestCategory, RegisterByMacro)
{
    ASSERT_NO_THROW({ reg(); });

    bool havePing = false, havePong = false;
    ping = [&](LSMessage *m) {
        havePing = true;
        LS::Error e;
        EXPECT_TRUE(LSMessageRespond(m, "{\"returnValue\":true, \"answer\":42}", e.get())) << e.what();
        return true;
    };
    pong = [&](LSMessage *m) {
        finish();
        havePong = true;
        auto response = pbnjson::JDomParser::fromString(LSMessageGetPayload(m));
        EXPECT_EQ(JValue(true), response["returnValue"]);
        return true;
    };

    LS::Error e;
    LSMessageToken token;
    EXPECT_TRUE(
        LSCallOneReply(
            sh_client.get(), "luna://com.palm.test/cbPing", "{}",
            wrap<&TestCategory::cbPong>(), this, &token,
            e.get()
        )
    ) << e.what();
    wait();
    EXPECT_TRUE(havePing);
    EXPECT_TRUE(havePong);
}

TEST_F(TestCategory, BasicScenario)
{
    LS::Error e;
    LSMessageToken token;
    bool havePong = false, havePing = false;

    // call to bare service (even without categories)
    pong = [&](LSMessage *m) {
        finish();
        havePong = true;
        auto response = pbnjson::JDomParser::fromString(LSMessageGetPayload(m));
        EXPECT_EQ(JValue(false), response["returnValue"]);
        EXPECT_EQ(JValue("Unknown method \"ping\" for category \"/\""), response["errorText"]) << response.stringify();
        return true;
    };

    EXPECT_TRUE(
        LSCallOneReply(
            sh_client.get(), "luna://com.palm.test/ping", "{}",
            wrap<&TestCategory::cbPong>(), this, &token,
            e.get()
        )
    ) << e.what();
    wait();
    ASSERT_TRUE(havePong);

    LSMethod methods[] = {
        { "ping", wrap<&TestCategory::cbPing>() },
        { nullptr, nullptr },
    };

    ASSERT_NO_THROW({ sh.registerCategory("/", methods, nullptr, nullptr); });
    ASSERT_NO_THROW({ sh.setCategoryData("/", this); });

    // call complete service for /ping
    havePing = havePong = false;
    ping = [&](LSMessage *m) {
        finish();
        havePing = true;
        LS::Error e;
        EXPECT_TRUE(LSMessageRespond(m, "{\"returnValue\":true, \"answer\":42}", e.get())) << e.what();
        return true;
    };
    pong = [&](LSMessage *m) {
        finish();
        havePong = true;
        auto response = pbnjson::JDomParser::fromString(LSMessageGetPayload(m));
        EXPECT_EQ(JValue(true), response["returnValue"]);
        EXPECT_EQ(JValue(42), response["answer"]);
        return true;
    };

    EXPECT_TRUE(
        LSCallOneReply(
            sh_client.get(), "luna://com.palm.test/ping", "{}",
            wrap<&TestCategory::cbPong>(), this, &token,
            e.get()
        )
    ) << e.what();
    wait();
    EXPECT_TRUE(havePing);
    wait();
    EXPECT_TRUE(havePong);
}

TEST_F(TestCategory, IntrospectionFlat)
{
    LSMethod methods[] = {
        { "ping", wrap<&TestCategory::cbPing>() },
        { nullptr, nullptr },
    };

    ASSERT_NO_THROW({ sh.registerCategory("/", methods, nullptr, nullptr); });

    LS::Call call;
    LS::Message reply;
    ASSERT_NO_THROW({ call = sh.callOneReply("luna://com.palm.test/com/palm/luna/private/introspection", "{}"); });
    ASSERT_NO_THROW({ reply = call.get(1000); });

    ASSERT_TRUE(bool(reply));
    auto response = pbnjson::JDomParser::fromString(reply.getPayload());
    auto simple_introspection = JValue
    {
        { "/", {
            { "ping", "METHOD"},
        }},
    };
    EXPECT_EQ(simple_introspection, response);
}

TEST_F(TestCategory, IntrospectionDescription)
{
    LSMethod methods[] = {
        { "ping", wrap<&TestCategory::cbPing>() },
        { nullptr, nullptr },
    };

    ASSERT_NO_THROW({ sh.registerCategory("/", methods, nullptr, nullptr); });

    auto description = JValue
    {
        { "methods", {
            { "ping", {
                { "call", {
                    { "type", "object" },
                    { "description", "simple ping" },
                    { "additionalProperties", false },
                }},
            }},
        }},
    };
    auto expected = description.duplicate();

    ASSERT_NO_THROW({ sh.setCategoryDescription("/", description.m_jval); });

    LS::Call call;
    LS::Message reply;
    ASSERT_NO_THROW({ call = sh.callOneReply("luna://com.palm.test/com/palm/luna/private/introspection", R""({"type": "description"})""); });
    ASSERT_NO_THROW({ reply = call.get(1000); });

    ASSERT_TRUE(bool(reply));
    EXPECT_EQ(description, expected);

    expected["methods"]["ping"].put("provides", pbnjson::JArray{ "private" });

    auto response = pbnjson::JDomParser::fromString(reply.getPayload());
    auto descr_introspection = JValue
    {
        { "returnValue", true },
        { "categories", {
            { "/", expected },
        }},
    };
    EXPECT_EQ(descr_introspection, response);
}

TEST_F(TestCategory, IntrospectionEffectiveMethods)
{
    LSMethod methods[] = {
        { "ping", wrap<&TestCategory::cbPing>() },
        { "ping2", wrap<&TestCategory::cbPing>() },
        { nullptr, nullptr },
    };

    ASSERT_NO_THROW({ sh.registerCategory("/", methods, nullptr, nullptr); });

    auto description = JValue
    {
        { "methods", {
            { "ping", {
                { "call", {
                    { "type", "object" },
                    { "description", "simple ping" },
                    { "additionalProperties", false },
                }},
            }},
            { "pong", {
                { "call", {
                    { "type", "object" },
                    { "description", "simple pong" },
                    { "additionalProperties", false },
                }},
            }},
        }},
    };
    auto expected = description.duplicate();

    ASSERT_NO_THROW({ sh.setCategoryDescription("/", description.m_jval); });

    LS::Call call;
    LS::Message reply;
    JValue response;

    EXPECT_NO_THROW({ call = sh.callOneReply("luna://com.palm.test/com/palm/luna/private/introspection", R""({"type": "description"})""); });
    EXPECT_NO_THROW({ reply = call.get(1000); });

    EXPECT_TRUE(bool(reply));
    EXPECT_EQ(description, expected);

    expected["methods"]["ping"].put("provides", pbnjson::JArray{ "private" });
    expected["methods"]["pong"].put("provides", pbnjson::JArray{ "private" });

    if (reply)
    {
        response = pbnjson::JDomParser::fromString(reply.getPayload());;
        auto answer_from_mixed_descr = JValue
        {
            { "returnValue", true },
            { "categories", {
                { "/", {
                    { "methods", {
                        { "ping", expected["methods"]["ping"] },
                        { "ping2", { { "provides", pbnjson::JArray{ "private" } } } },
                    }},
                } },
            }},
        };
        EXPECT_EQ(answer_from_mixed_descr, response);
    }

    LSMethod method_pong[] = {
        { "pong", wrap<&TestCategory::cbPing>() },
        { nullptr, nullptr },
    };

    ASSERT_NO_THROW({ sh.registerCategoryAppend("/", method_pong, nullptr); });

    EXPECT_NO_THROW({ call = sh.callOneReply("luna://com.palm.test/com/palm/luna/private/introspection", R""({"type": "description"})""); });
    reply = {};
    EXPECT_NO_THROW({ reply = call.get(1000); });

    EXPECT_TRUE(bool(reply));
    if (reply)
    {
        response = pbnjson::JDomParser::fromString(reply.getPayload());;
        auto answer_from_mixed_descr = JValue
        {
            { "returnValue", true },
            { "categories", {
                { "/", {
                    { "methods", {
                        { "ping", expected["methods"]["ping"] },
                        { "pong", expected["methods"]["pong"] },
                        { "ping2", { { "provides", pbnjson::JArray{ "private" } } } },
                    }},
                } },
            }},
        };
        EXPECT_EQ(answer_from_mixed_descr, response);
    }
}

TEST_F(TestCategory, IntrospectionBad)
{
    LSMethod methods[] = {
        { "ping", wrap<&TestCategory::cbPing>() },
        { nullptr, nullptr },
    };

    ASSERT_NO_THROW({ sh.registerCategory("/", methods, nullptr, nullptr); });

    LS::Call call;
    LS::Message reply;
    JValue response;

    SCOPED_TRACE("introspection while no description");

    EXPECT_NO_THROW({ call = sh.callOneReply("luna://com.palm.test/com/palm/luna/private/introspection", R""({"type": "description"})""); });
    EXPECT_NO_THROW({ reply = call.get(1000); });

    EXPECT_TRUE(bool(reply));
    if (reply)
    {
        response = pbnjson::JDomParser::fromString(reply.getPayload());
        auto answer_for_no_description = JValue
        {
            { "returnValue", true },
            { "categories", {
                { "/", {
                    { "methods", {
                        { "ping", { { "provides", pbnjson::JArray{ "private" } } } },
                    }},
                } },
            }},
        };
        EXPECT_EQ(answer_for_no_description, response);
    }

    auto description = JValue
    {
        { "methods", {
            { "ping", {
                { "call", {
                    { "type", "object" },
                    { "description", "simple ping" },
                    { "additionalProperties", false },
                }},
            }},
        }},
    };

    EXPECT_NO_THROW({ sh.setCategoryDescription("/", description.m_jval); });

    SCOPED_TRACE("introspection with a wrong type in params");
    EXPECT_NO_THROW({ call = sh.callOneReply("luna://com.palm.test/com/palm/luna/private/introspection", R""({"type": "wrong"})""); });
    reply = {};
    EXPECT_NO_THROW({ reply = call.get(1000); });

    EXPECT_TRUE(bool(reply));
    if (reply)
    {
        response = pbnjson::JDomParser::fromString(reply.getPayload());
        EXPECT_EQ(JValue(false), response["returnValue"])
            << "Expected schema failure but got response: " << ::testing::PrintToString(response);
    }
}

TEST_F(TestCategory, Validation)
{
    LS::Error e;
    LSMessageToken token;

    LSMethod methods[] = {
        { "ping", wrap<&TestCategory::cbPing>(), LUNA_METHOD_FLAG_VALIDATE_IN },
        { nullptr, nullptr },
    };

    ASSERT_NO_THROW({ sh.registerCategory("/", methods, nullptr, nullptr); });
    ASSERT_NO_THROW({ sh.setCategoryData("/", this); });

    auto description = JValue
    {
        { "methods", {
            { "ping", {
                { "call", {
                    { "type", "object" },
                    { "description", "simple ping" },
                    { "additionalProperties", false },
                }},
            }},
        }},
    };

    ASSERT_NO_THROW({ sh.setCategoryDescription( "/", description.m_jval); });

    bool havePong = false, havePing = false;
    ping = [&](LSMessage *m) {
        finish();
        havePing = true;
        auto params = pbnjson::JDomParser::fromString(LSMessageGetPayload(m));
        EXPECT_TRUE( params.isObject() );
        LS::Error e;
        EXPECT_TRUE(LSMessageRespond(m, "{\"returnValue\":true, \"answer\":42}", e.get())) << e.what();
        return true;
    };
    pong = [&](LSMessage *m) {
        finish();
        havePong = true;
        auto response = pbnjson::JDomParser::fromString(LSMessageGetPayload(m));
        EXPECT_EQ(JValue(false), response["returnValue"]);
        return true;
    };
    EXPECT_TRUE(
        LSCallOneReply(
            sh_client.get(), "luna://com.palm.test/ping", "{\"wrong\":42}",
            wrap<&TestCategory::cbPong>(), this, &token,
            e.get()
        )
    ) << e.what();

    wait();
    EXPECT_FALSE(havePing);
    if (havePing) wait();
    EXPECT_TRUE(havePong);

    havePong = havePing = false;

    pong = [&](LSMessage *m) {
        finish();
        havePong = true;
        auto response = pbnjson::JDomParser::fromString(LSMessageGetPayload(m));
        EXPECT_EQ(JValue(true), response["returnValue"]);
        EXPECT_EQ(JValue(42), response["answer"]);
        return true;
    };

    EXPECT_TRUE(
        LSCallOneReply(
            sh_client.get(), "luna://com.palm.test/ping", "{}",
            wrap<&TestCategory::cbPong>(), this, &token,
            e.get()
        )
    ) << e.what();

    wait();
    EXPECT_TRUE(havePing);
    wait();
    EXPECT_TRUE(havePong);
}
