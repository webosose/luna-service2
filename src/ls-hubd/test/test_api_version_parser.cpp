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

#include <iostream>
#include <vector>

#include <luna-service2/lunaservice.hpp>
#include <gtest/gtest.h>
#include <pbnjson.hpp>

#include "../hub.hpp"
#include "../permission.hpp"
#include "../file_parser.hpp"
#include "../permissions_map.hpp"
#include "../service_permissions.hpp"
#include "../security.hpp"

static std::string error_msg;

class VersionParser : public ::testing::Test
{
protected:
    void SetUp() override
    {
    }

    void parseJsons(std::vector<std::string> jsons)
    {
        PermissionArray perms;
        perms.push_back(mk_ptr(LSHubPermissionNewRef("com.webos.foo", "/usr/bin/foo"), LSHubPermissionUnref));
        perms.push_back(mk_ptr(LSHubPermissionNewRef("com.webos.bar", "/usr/bin/bar"), LSHubPermissionUnref));

        for (auto &json: jsons)
        {
            LS::Error error;
            ASSERT_TRUE(_parser.parse(json, pbnjson::JSchema::AllSchema()));

            ParseJSONGetAPIVersions(_parser.getDom(), "localhost", perms, error);
            if (error.isSet())
            {
                error_msg = error.get()->message;
                return;
            }
        }

        for (auto & perm : perms)
        {
            PermissionsMap &pmap = SecurityData::CurrentSecurityData().permissions;
            pmap.Add(std::move(perm));
        }
    }

    std::string valid_json = R"json({
        "versions": {
            "com.webos.foo": "0.1",
            "com.webos.bar": "4.2"
        }
     })json";

    std::string invalid_json = R"json({
        "versions": []
    })json";

    std::string unknown_service_json = R"json({
        "versions": {
            "com.webos.foo": "0.1"
        }
    })json";

    std::string service_duplication_json = R"json({
        "versions": {
            "com.webos.foo": "0.1"
        }
    })json";

    pbnjson::JDomParser _parser;
};

TEST_F(VersionParser, VersionParserTest)
{
    auto getVersion = [](const std::string &sname, const std::string &exe) -> const pbnjson::JValue
    {
        PermissionsMap &pmap = SecurityData::CurrentSecurityData().permissions;
        auto permission = pmap.LookupServicePermissions(sname.c_str());

        return permission
                ? LSHubPermissionGetAPIVersion(LSHubServicePermissionsLookupPermission(permission, exe.c_str()))
                : pbnjson::JValue();
    };


    parseJsons({valid_json});
    EXPECT_EQ(getVersion("com.webos.foo", "/usr/bin/foo"), pbnjson::JValue("0.1"));
    EXPECT_EQ(getVersion("com.webos.bar", "/usr/bin/bar"), pbnjson::JValue("4.2"));
    EXPECT_TRUE(error_msg.empty());

    parseJsons({valid_json, service_duplication_json});
    EXPECT_EQ(error_msg, "Error reading version from the JSON file: localhost. "
                         "'com.webos.foo' service already has version set to '0.1'.");
    error_msg.clear();
}

int
main(int argc, char *argv[])
{
    ::testing::InitGoogleTest(&argc, argv);

    return RUN_ALL_TESTS();
}
