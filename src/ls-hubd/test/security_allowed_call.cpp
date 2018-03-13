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

#include <gtest/gtest.h>
#include "luna-service2/lunaservice.hpp"
#include <pbnjson.hpp>

#include "test_util.hpp"

static bool MethodStub(LSHandle *sh, LSMessage *message, void *data)
{
    LSMessageRespond(message, "{}", nullptr);
    return true;
}

TEST(TestAllowedCall, Yes)
{
    auto customer = LS::registerApplicationService("com.webos.customer", nullptr);
    auto agent    = LS::registerApplicationService("com.webos.agent", nullptr);
    auto product  = LS::registerApplicationService("com.webos.product", nullptr);

    MainLoopT mainloop;

    customer.attachToLoop(mainloop.get());
    agent.attachToLoop(mainloop.get());
    product.attachToLoop(mainloop.get());

    static LSMethod methods[] =
    {
        { "foo", MethodStub, LUNA_METHOD_FLAGS_NONE },
        { "bar", MethodStub, LUNA_METHOD_FLAGS_NONE },
        { nullptr }
    };
    product.registerCategory("/get", methods, nullptr, nullptr);
    product.registerCategory("/set", methods, nullptr, nullptr);

    auto reply = agent.callOneReply("luna://com.webos.service.bus/isCallAllowed",
                                    R"({"requester": "com.webos.customer", "uri": "luna://com.webos.product/get/foo"})").get();
    EXPECT_TRUE(bool(reply));
    EXPECT_FALSE(reply.isHubError());
    EXPECT_EQ(std::string(R"({"returnValue": true, "allowed": true})"),
              std::string(reply.getPayload()));

    reply = agent.callOneReply("luna://com.webos.service.bus/isCallAllowed",
                               R"({"requester": "com.webos.customer", "uri": "luna://com.webos.product/set/bar"})").get();
    EXPECT_TRUE(bool(reply));
    EXPECT_FALSE(reply.isHubError());
    EXPECT_EQ(std::string(R"({"returnValue": true, "allowed": true})"),
              std::string(reply.getPayload()));
}

TEST(TestAllowedCall, No)
{
    auto customer = LS::registerApplicationService("com.webos.customer", nullptr);
    auto agent    = LS::registerApplicationService("com.webos.agent", nullptr);
    auto product  = LS::registerApplicationService("com.webos.product", nullptr);

    MainLoopT mainloop;

    customer.attachToLoop(mainloop.get());
    agent.attachToLoop(mainloop.get());
    product.attachToLoop(mainloop.get());

    static LSMethod methods[] =
    {
        { "foo", MethodStub, LUNA_METHOD_FLAGS_NONE },
        { "bar", MethodStub, LUNA_METHOD_FLAGS_NONE },
        { nullptr }
    };
    product.registerCategory("/get", methods, nullptr, nullptr);
    product.registerCategory("/set", methods, nullptr, nullptr);

    auto reply = agent.callOneReply("luna://com.webos.service.bus/isCallAllowed",
                                    R"({"requester": "com.webos.customer", "uri": "luna://com.webos.product/set/foo"})").get();
    EXPECT_TRUE(bool(reply));
    EXPECT_FALSE(reply.isHubError());
    EXPECT_EQ(std::string(R"({"returnValue": true, "allowed": false})"),
              std::string(reply.getPayload()));

    reply = agent.callOneReply("luna://com.webos.service.bus/isCallAllowed",
                               R"({"requester": "com.webos.customer", "uri": "luna://com.webos.product/get/bar"})").get();
    EXPECT_TRUE(bool(reply));
    EXPECT_FALSE(reply.isHubError());
    EXPECT_EQ(std::string(R"({"returnValue": true, "allowed": false})"),
              std::string(reply.getPayload()));
}

TEST(TestAllowedCall, Error)
{
    auto agent = LS::registerApplicationService("com.webos.agent", nullptr);

    MainLoopT mainloop;
    agent.attachToLoop(mainloop.get());

    auto reply = agent.callOneReply("luna://com.webos.service.bus/isCallAllowed",
                                  R"({"requester": "com.webos.customer", "uri": "http://any.com"})").get();

    // uri error
    auto object = pbnjson::JDomParser::fromString(reply.getPayload());
    EXPECT_FALSE(object["returnValue"].asBool());
    EXPECT_EQ(object["errorCode"].asNumber<int>(), -EINVAL);

    EXPECT_FALSE(reply.isHubError());
    EXPECT_TRUE(std::string(reply.getPayload()).find("\"returnValue\": false") != std::string::npos);

    reply = agent.callOneReply("luna://com.webos.service.bus/isCallAllowed",
                                    R"({"requester": "com.webos.customer"})").get();
    // schema error
    object = pbnjson::JDomParser::fromString(reply.getPayload());
    EXPECT_FALSE(object["returnValue"].asBool());
    EXPECT_EQ(object["errorCode"].asNumber<int>(), -1);

    reply = agent.callOneReply("luna://com.webos.service.bus/isCallAllowed",
                   R"({"uri": "luna://com.webos.product/get/bar"})").get();

    // schema error
    object = pbnjson::JDomParser::fromString(reply.getPayload());
    EXPECT_FALSE(object["returnValue"].asBool());
    EXPECT_EQ(object["errorCode"].asNumber<int>(), -1);
}

TEST(TestAllowedCall, UniqueName)
{
    //   caller -> caller/test_method                     # Self call to be able to get unique name
    //     caller -> isCallAllowed(test/method_allowed)
    //     caller -> isCallAllowed(test/method_disallowed)

    auto caller = LS::registerService("com.unique.caller");

    MainLoopT mainloop;

    caller.attachToLoop(mainloop.get());

    auto test_method = [](LSHandle *sh, LSMessage *message, void *data) -> bool
    {
        const auto CALL_ALLOWED = pbnjson::JObject{{"returnValue", true}, {"allowed", true}};
        const auto CALL_NOT_ALLOWED = pbnjson::JObject{{"returnValue", true}, {"allowed", false}};

        LS::Handle &caller = *(LS::Handle *) data;
        LS::Message request{message};

        auto form_payload = [](const char *requester, const char *uri) -> std::string
        {
            auto v = pbnjson::JObject{{"requester", requester}, {"uri", uri}};
            return v.stringify();
        };

        {
            // Check that a call is allowed by requester service name
            auto reply = caller.callOneReply("luna://com.webos.service.bus/isCallAllowed",
                                             form_payload(request.getSenderServiceName(),
                                                          "luna://com.unique.test/method_allowed").c_str()).get();
            EXPECT_EQ(CALL_ALLOWED, pbnjson::JDomParser::fromString(reply.getPayload()));
        }

        {
            // Check that a call is allowed by requester unique name
            auto reply = caller.callOneReply("luna://com.webos.service.bus/isCallAllowed",
                                             form_payload(request.getSender(),
                                                          "luna://com.unique.test/method_allowed").c_str()).get();
            EXPECT_EQ(CALL_ALLOWED, pbnjson::JDomParser::fromString(reply.getPayload()));
        }

        {
            // Check that a call is disallowed by requester service name
            auto reply = caller.callOneReply("luna://com.webos.service.bus/isCallAllowed",
                                             form_payload(request.getSenderServiceName(),
                                                          "luna://com.unique.test/method_disallowed").c_str()).get();
            EXPECT_EQ(CALL_NOT_ALLOWED, pbnjson::JDomParser::fromString(reply.getPayload()));
        }

        {
            // Check that a call is disallowed by requester unique name
            auto reply = caller.callOneReply("luna://com.webos.service.bus/isCallAllowed",
                                             form_payload(request.getSender(),
                                                          "luna://com.unique.test/method_disallowed").c_str()).get();
            EXPECT_EQ(CALL_NOT_ALLOWED, pbnjson::JDomParser::fromString(reply.getPayload()));
        }

        LSMessageRespond(message, "{}", nullptr);
        return true;
    };

    static LSMethod caller_methods[] =
    {
        { "test_method", test_method, LUNA_METHOD_FLAGS_NONE },
        { nullptr },
    };
    caller.registerCategory("/", caller_methods, nullptr, nullptr);
    caller.setCategoryData("/", &caller);

    auto reply = caller.callOneReply("luna://com.unique.caller/test_method", "{}").get();
    ASSERT_EQ(reply.getPayload(), std::string("{}"));
}
