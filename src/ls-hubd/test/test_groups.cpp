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

#include <glib.h>
#include <iostream>
#include <sstream>
#include <string>
#include <gtest/gtest.h>

#include <luna-service2/lunaservice.h>

#include "../security.hpp"
#include "../permission.hpp"
#include "../groups_map.hpp"
#include "../patternqueue.hpp"

using namespace std;

class GroupParser : public ::testing::Test
{
protected:
    void SetUp() override
    {
        pbnjson::JDomParser parser;
        ASSERT_TRUE(parser.parse(groups, pbnjson::JSchema::AllSchema()));

        json = parser.getDom();

    }

    void fillGroupTree(SecurityData &sdata)
    {
        LSError err;
        LSErrorInit(&err);

        for (const auto &g : json.children())
        {
            for (const auto &p : g.second.items())
            {
                sdata.groups.AddProvided(getServiceNameFromUri(p.asString()).c_str(),
                                         p.asString().c_str(),
                                         g.first.asString().c_str());
            }
        }
    }

    std::string groups = R"json({
            "media": ["com.webos.umediapipeline.*", "com.webos.umediaserver"],
            "contacts": ["com.webos.contacts", "com.webos.lg.*"],
            "public": ["com.webos.*/public/*", "com.palm.*/public"]
     })json";

    pbnjson::JValue json;
};

TEST_F(GroupParser, GroupManageTest)
{
    SecurityData sdata;
    fillGroupTree(sdata);
    SecurityData::CurrentSecurityData() = std::move(sdata);

    const char *public_str = g_intern_string("public");
    const char *contacts_str = g_intern_string("contacts");

    ASSERT_EQ(SecurityData::CurrentSecurityData().groups.GetProvided("com.webos.contacts"),
              (CategoryMap{ {"/public/*", {public_str}}, {"/", {contacts_str}} }));

    sdata = SecurityData();
    fillGroupTree(sdata);
    sdata.groups.AddProvided("com.webos.cont*", "com.webos.cont*", "facebook");
    SecurityData::CurrentSecurityData() = std::move(sdata);

    const char *facebook_str = g_intern_string("facebook");

    ASSERT_EQ(SecurityData::CurrentSecurityData().groups.GetProvided("com.webos.contacts"),
              (CategoryMap{
                  {"/public/*", {public_str}},
                  {"/", {contacts_str, facebook_str}}
                  }));
}

int
main(int argc, char *argv[])
{
    ::testing::InitGoogleTest(&argc, argv);

    return RUN_ALL_TESTS();
}
