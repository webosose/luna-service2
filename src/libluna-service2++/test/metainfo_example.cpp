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

#include <thread>
#include <string>
#include <cassert>
#include <iostream>

#define private public
#include <pbnjson.hpp>
#undef private

#include <luna-service2/lunaservice.hpp>
#include <luna-service2/lunaservice-meta.h>

#include "test_util.hpp"

// Service class which uses schemas for category methods
class TestMetaInfoService: public LS::Handle
{

public:
    explicit TestMetaInfoService(GMainLoop* loop)
        : LS::Handle{LS::registerService("com.palm.metainfo_example")}
        , _category{"/testMethods"}
    {
        LS_CATEGORY_BEGIN(TestMetaInfoService, _category.c_str())
            LS_CATEGORY_METHOD(testCall, LUNA_METHOD_FLAG_VALIDATE_IN)
        LS_CATEGORY_END

        attachToLoop(loop);
    }

    ~TestMetaInfoService()
    {
        detach();
    }

    bool testCall(LSMessage &message)
    {
        LS::Error error;
        LSMessageRespond(&message, R"({"returnValue":true})", error.get());
        return true;
    }

    void setCategorySchema(const std::string &schema)
    {
        setCategoryDescription(_category.c_str(), pbnjson::JDomParser::fromString(schema).m_jval);
    }

private:
    std::string _category;
};

namespace
{

std::string basicSchema = R"json(
{
"definitions": {
    "successResponse": {
        "type": "object",
        "description": "general successful response schema",
        "properties": {
            "returnValue": {
                "type": "boolean",
                "description": "call successful result indicator",
                "enum": [true]
            }
        },
        "required": ["returnValue"]
    },
    "errorResponse": {
        "type": "object",
        "description": "general error response schema",
        "properties": {
            "returnValue": {
                "type": "boolean",
                "description": "call unsuccessful result indicator",
                "enum": [false]
            },
            "errorCode": {
                "type": "integer",
                "description": "type of error indicator for client service"
            },
            "errorText": {
                "type": "string",
                "description": "human-readable error description"
            }
        },
        "required": ["returnValue"]
    }
},
"methods": {
    "testCall": {
        "call": {
            "type": "object",
            "description": "test call basic schema",
            "properties": {
                "id": { "type": "integer", "minimum": 0, "exclusiveMinimum": true }
            },
            "required": ["id"],
            "additionalProperties": true
        },
        "reply": {
            "oneOf": [
                { "$ref": "#/definitions/successResponse" },
                { "$ref": "#/definitions/errorResponse" }
            ]
        }
    }
}
}
)json";

std::string extSchema = R"json(
{
"definitions": {
    "client": {
        "description": "schema for client object",
        "type": "object",
        "properties": {
            "name": { "type": "string", "minLength": 2, "maxLength": 10 },
            "organization": { "type": "string" }
        },
        "required": ["name"],
        "additionalProperties": false
    },
    "successResponse": {
        "type": "object",
        "description": "general successful response schema",
        "properties": {
            "returnValue": {
                "type": "boolean",
                "description": "call successful result indicator",
                "enum": [true]
            }
        },
        "required": ["returnValue"]
    },
    "errorResponse": {
        "type": "object",
        "description": "general error response schema",
        "properties": {
            "returnValue": {
                "type": "boolean",
                "description": "call unsuccessful result indicator",
                "enum": [false]
            },
            "errorCode": {
                "type": "integer",
                "description": "type of error indicator for client service"
            },
            "errorText": {
                "type": "string",
                "description": "human-readable error description"
            }
        },
        "required": ["returnValue"]
    }
},
"methods": {
    "testCall": {
        "call": {
            "type": "object",
            "description": "test call request schema",
            "properties": {
                "id": { "type": "integer", "minimum": 0, "exclusiveMinimum": true },
                "sender": { "$ref": "#/definitions/client" }
            },
            "required": ["id", "sender"],
            "additionalProperties": true
        },
        "firstReply": {
            "oneOf": [
                { "$ref": "#/definitions/successResponse" },
                { "$ref": "#/definitions/errorResponse" }
            ]
        },
        "reply": {
            "type": "object",
            "description": "test call reply schema",
            "properties": {
                "timestamp": { "type": "string" }
            },
            "additionalProperties": true
        }
    }
}
}
)json";

} // anonymous

static bool returnValue(const LS::Message &message)
{
    return pbnjson::JDomParser::fromString(message.getPayload())["returnValue"].asBool();
}

// Example how to use JSON schema for call validation
TEST(TestMetaInfo, Validation)
{
    MainLoopT loop;

    TestMetaInfoService service(loop.get());
    LS::Handle client = LS::registerService();
    client.attachToLoop(loop.get());

    // No validation schema for testCall
    // Call with empty payload - success
    auto reply = client.callOneReply("luna://com.palm.metainfo_example/testMethods/testCall", "{}").get();
    ASSERT_TRUE(returnValue(reply));

//! [call validation]
    // Set schema for testCall
    // Mandatory parameters:
    //  numeric "id" > 0
    service.setCategorySchema(basicSchema);

    // Call with empty payload - fail call validation
    reply = client.callOneReply("luna://com.palm.metainfo_example/testMethods/testCall", "{}").get();
    ASSERT_TRUE(!returnValue(reply));

    // Call with invalid "id" value - fail call validation
    reply = client.callOneReply("luna://com.palm.metainfo_example/testMethods/testCall", R"({"id":-1})").get();
    ASSERT_TRUE(!returnValue(reply));

    // Call with valid "id" value - success call validation
    reply = client.callOneReply("luna://com.palm.metainfo_example/testMethods/testCall", R"({"id":1})").get();
    ASSERT_TRUE(returnValue(reply));

    // Set new schema for testCall
    // Mandatory parameters:
    //  numeric "id" > 0
    //  object "sender" with properties:
    //   "name" - mandatory string from 2 to 10 characters
    //   "organization" - optional string
    //   no additional properties allowed
    service.setCategorySchema(extSchema);

    // Call without "sender" object - fail call validation
    reply = client.callOneReply("luna://com.palm.metainfo_example/testMethods/testCall", R"({"id":1})").get();
    ASSERT_TRUE(!returnValue(reply));

    // Call testCall with invalid "sender" object - "name" is missing - fail call validation
    reply = client.callOneReply("luna://com.palm.metainfo_example/testMethods/testCall",
        R"({"id":1, "sender": {"organization": "LGE"}})").get();
    ASSERT_TRUE(!returnValue(reply));

    // Call testCall with invalid "sender" object - added additional property - fail call validation
    reply = client.callOneReply("luna://com.palm.metainfo_example/testMethods/testCall",
        R"({"id":1, "sender": {"name": "Test service", "addKey": "addValue"}})").get();
    ASSERT_TRUE(!returnValue(reply));

    // Call testCall with valid "sender" object - success call validation
    reply = client.callOneReply("luna://com.palm.metainfo_example/testMethods/testCall",
        R"({"id":1, "sender": {"name": "test", "organization": "LGE"}})").get();
    ASSERT_TRUE(returnValue(reply));
//! [call validation]

    loop.stop();
}

// Example how to use JSON schema for category introspection
TEST(TestMetaInfo, Introspection)
{
    MainLoopT loop;

    TestMetaInfoService service(loop.get());
    LS::Handle client = LS::registerService();
    client.attachToLoop(loop.get());

//! [category introspection]
    // Set schema for category
    service.setCategorySchema(extSchema);

    // Call category introspection information
    auto reply = client.callOneReply("luna://com.palm.metainfo_example/com/palm/luna/private/introspection",
        R"({"type":"description"})").get();
    ASSERT_TRUE(returnValue(reply));

    auto data = pbnjson::JDomParser::fromString(reply.getPayload());
    ASSERT_TRUE(data.hasKey("categories"));

    // Retrieve categories
    auto cats = data["categories"];
    std::cout << "Category: " << (*cats.children().begin()).first.asString() << std::endl;

    // Retrieve methods for first category
    auto methods = (*cats.children().begin()).second["methods"];
    // Iterate through methods and print assigned schemas
    for (const auto &m : methods.children())
    {
        std::cout << " Method: " << m.first.asString() << std::endl;
        auto method = m.second;
        ASSERT_TRUE(method.hasKey("call"));
        std::cout << "  Call schema: " << method["call"].stringify("  ") << std::endl;

        if (method.hasKey("firstReply"))
        {
            std::cout << "  First reply schema: " << method["firstReply"].stringify("  ") << std::endl;
        }

        if (method.hasKey("reply"))
        {
            std::cout << "  Reply schema: " << method["reply"].stringify("  ") << std::endl;
        }

    }
//! [category introspection]

    loop.stop();
}
