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

#include <thread>
#include <unordered_map>

#include <gtest/gtest.h>
#include <luna-service2/lunaservice.hpp>
#include <pbnjson.hpp>

#include "test_util.hpp"

using namespace std;
using namespace pbnjson;

static const unordered_map<string, string> versions =
{
    {"com.webos.test1", "4.2"},
    {"com.webos.test2", "1.9"},
    {"com.webos.test3", "2.92"}
};

TEST(TestValidVersions, Versions)
{
    auto api_requester = LS::registerApplicationService("com.webos.request.service", nullptr);

    MainLoopT mainloop;
    api_requester.attachToLoop(mainloop.get());

    for (const auto &version: versions)
    {
        JObject tjson = {{"versions", JObject{{version.first, version.second}}}, {"returnValue", true}};
        LS::Message reply = api_requester.callOneReply("luna://com.webos.service.bus/getServiceAPIVersions",
                                string(R"({"services": [")" + version.first + R"("]})").c_str()).get();
        EXPECT_TRUE(bool(reply));
        EXPECT_FALSE(reply.isHubError());
        EXPECT_EQ(tjson, JDomParser().fromString(reply.getPayload()));
    }

    JObject fjson = {{"unknown", JArray{"com.palm.1","com.palm.2"}}, {"versions", JObject()}, {"returnValue", false}};
    LS::Message invalid_reply = api_requester.callOneReply("luna://com.webos.service.bus/getServiceAPIVersions",
                                    string(R"({"services": ["com.palm.1", "com.palm.2"]})").c_str()).get();
    EXPECT_TRUE(bool(invalid_reply));
    EXPECT_FALSE(invalid_reply.isHubError());
    EXPECT_EQ(fjson, JDomParser().fromString(invalid_reply.getPayload()));
}

TEST(TestValidVersions, Cancel)
{
    auto api_requester = LS::registerApplicationService("com.webos.request.service", nullptr);

    MainLoopT mainloop;
    api_requester.attachToLoop(mainloop.get());

    for (const auto &version: versions)
    {
        JObject tjson = {{"versions", JObject{{version.first, version.second}}}, {"returnValue", true}};
        LS::Call call = api_requester.callMultiReply("luna://com.webos.service.bus/getServiceAPIVersions",
                                string(R"({"services": [")" + version.first + R"("]})").c_str());
        LS::Message reply = call.get();
        EXPECT_TRUE(bool(reply));

        ASSERT_TRUE(call.isActive());
        call.cancel();
        ASSERT_FALSE(call.isActive());
    }
}

int
main(int argc, char *argv[])
{
    ::testing::InitGoogleTest(&argc, argv);

    return RUN_ALL_TESTS();
}
