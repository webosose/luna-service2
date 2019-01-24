// Copyright (c) 2016-2019 LG Electronics, Inc.
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

TEST(Introspection, Flat)
{
    MainLoop main_loop;

    auto client = LS::registerService("com.webos.client");
    client.attachToLoop(main_loop.get());

    auto call = client.callOneReply("luna://com.webos.service/com/palm/luna/private/introspection", "{}");
    auto reply = call.get(1000);
    ASSERT_NE(nullptr, reply.get());

    auto payload = pbnjson::JDomParser::fromString(reply.getPayload());
    auto reference = pbnjson::JDomParser::fromString(R"(
{
    "/": {
        "quit": "METHOD"
    }
}
    )");

    EXPECT_TRUE(reference == payload)
        << "Expected:\n" << reference.stringify("  ")
        << "Actual:\n" << payload.stringify("  ");
}

TEST(Introspection, Description)
{
    MainLoop main_loop;

    auto client = LS::registerService("com.webos.client");
    client.attachToLoop(main_loop.get());

    auto call = client.callOneReply("luna://com.webos.service/com/palm/luna/private/introspection",
                                    R"({"type": "description"})");
    auto reply = call.get(1000);
    ASSERT_NE(nullptr, reply.get());

    auto payload = pbnjson::JDomParser::fromString(reply.getPayload());
    static auto payload_schema = pbnjson::JSchema::fromString(R"(
{
    "type": "object",
    "properties": {
        "returnValue": {"enum": [true]},
        "categories": {
            "additionalProperties": {
                "type": "object",
                "properties": {
                    "methods": {
                        "type": "object",
                        "additionalProperties": {
                            "type": "object",
                            "properties": {
                                "provides": {
                                    "type": "array",
                                    "items": {"type": "string"}
                                }
                            }
                        }
                    }
                }
            }
        }
    },
    "additionalProperties": false
}
    )");
    auto result = payload_schema.validate(payload);
    ASSERT_TRUE(!result.isError()) << result.errorString();

    ASSERT_EQ(1, payload["categories"]["/"]["methods"].objectSize());

    typedef std::set<std::string> SetT;

    auto create_set = [](const pbnjson::JValue &val) -> SetT
    {
        SetT ret;
        for (const auto s : val.items())
            ret.insert(s.asString());
        return ret;
    };

    EXPECT_EQ(SetT({"q"}), create_set(payload["categories"]["/"]["methods"]["quit"]["provides"]));
}

TEST(Introspection, Quit)
{
    MainLoop main_loop;

    auto client = LS::registerService("com.webos.client");
    client.attachToLoop(main_loop.get());

    auto call = client.callOneReply("luna://com.webos.service/quit", "{}");
    call.get();
}
