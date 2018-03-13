// Copyright (c) 2016-2018 LG Electronics, Inc.
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
#include <set>
#include <map>

#include "test_util.hpp"

typedef std::set<std::string> Groups;

Groups FromArray(pbnjson::JValue groups)
{
    Groups result;
    for (auto g : groups.items())
        result.emplace(g.asString());
    return result;
}

TEST(TestQueryPermissions, First)
{
    MainLoopT main_loop;
    auto handle = LS::registerService("com.webos.service");
    handle.attachToLoop(main_loop.get());

    auto reply = handle.callOneReply("luna://com.webos.service.bus/queryServicePermissions",
                                     R"({"service": "com.webos.service"})").get();
    EXPECT_TRUE(bool(reply));
    EXPECT_FALSE(reply.isHubError());
    auto val = pbnjson::JDomParser::fromString(reply.getPayload());
    ASSERT_TRUE(val["returnValue"].asBool()) << "com.webos.service.bus/queryServicePermissions failed";

    auto client_permissions = val["client"];
    EXPECT_EQ(Groups({"media", "audio", "database", "webos"}), FromArray(client_permissions)) << "client permissions mismatch";

    auto api_permissions = val["api"];
    EXPECT_EQ(5, api_permissions.objectSize());
    EXPECT_EQ(Groups({"all", "service.all"}), FromArray(api_permissions["/*"]));
    EXPECT_EQ(Groups({"service.get"}), FromArray(api_permissions["/get*"]));
    EXPECT_EQ(Groups({"service.put"}), FromArray(api_permissions["/put/*"]));
    EXPECT_EQ(Groups({"service.monitor"}), FromArray(api_permissions["/monitor"]));
    EXPECT_EQ(Groups({"get.one"}), FromArray(api_permissions["/getOne"]));
}
