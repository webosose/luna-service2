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

#include <pbnjson.hpp>
#include <luna-service2++/error.hpp>

#include "test_security_util.hpp"

#define private public
#include "../conf.hpp"
#include "../file_schema.hpp"
#include "../file_parser.hpp"
#include "../security.hpp"
#include "../role.hpp"
#include "../permission.hpp"
#undef private

static const std::string &manifests = manifests_dir;

TEST(TestManifest, TestInternal)
{
    std::string v1 = manifests + "/v1.manifest.json";
    std::string v2 = manifests + "/v2.manifest.json";
    std::string any = manifests + "/any.manifest.json";
    std::string invalid = manifests + "/invalid.manifest.json";

    LS::Error error;
    SecurityData security;
    EXPECT_TRUE(security.AddManifest(v1, manifests, error));
    EXPECT_TRUE(security.AddManifest(v2, manifests, error));
    EXPECT_TRUE(security.AddManifest(any, manifests, error));
    EXPECT_FALSE(security.AddManifest(invalid, manifests, error));

    const auto &all = security._manifests;

    EXPECT_TRUE(all.find(Manifest(v1)) != all.end());
    EXPECT_TRUE(all.find(Manifest(v2)) != all.end());
    EXPECT_TRUE(all.find(Manifest(any)) != all.end());
    EXPECT_FALSE(all.find(Manifest(invalid)) != all.end());

    const auto &priority = security._manifests_priority;

    EXPECT_TRUE(priority.find("test") != priority.end());
    EXPECT_TRUE(priority.find("any") != priority.end());

    security.RemoveManifest(any);
    EXPECT_FALSE(all.find(Manifest(any)) != all.end());
    EXPECT_FALSE(priority.find("any") != priority.end());

    security.RemoveManifest(v2);
    EXPECT_FALSE(all.find(Manifest(v2)) != all.end());
    EXPECT_TRUE(priority.find("test") != priority.end());
}

static inline
void validate(SecurityData &security, const char *id, const char *name,
              const pbnjson::JArray &jreqs, const pbnjson::JObject &jprovs)
{
    Groups reqs;
    for (const auto &item : jreqs.items())
    {
        reqs.push_back(g_intern_string(item.asString().c_str()));
    }
    EXPECT_EQ(security.groups.GetRequired(name), reqs);

    CategoryMap provs;
    for (const auto &child : jprovs.children())
    {
        auto cat = child.first.asString();
        for (const auto &item : child.second.items())
        {
            provs[cat].push_back(g_intern_string(item.asString().c_str()));
        }
    }
    EXPECT_EQ(provs, security.groups.GetProvided(name));

    auto perm = security.permissions.Lookup(name, id);
    ASSERT_TRUE(perm);

    LSHubPermissionSetRequired(perm, reqs);
    LSHubPermissionSetProvided(perm, provs);

    pbnjson::JObject obj;
    obj.put("service", name);
    obj.put("executable", id);
    obj.put("inbound", pbnjson::JArray{"com.webos.in"});
    obj.put("outbound", pbnjson::JArray{"com.webos.out"});
    obj.put("requires", jreqs);
    obj.put("provides", jprovs);

    pbnjson::JDomParser parser;
    ASSERT_TRUE(parser.parse(LSHubPermissionDump(perm), pbnjson::JSchema::AllSchema()));

    EXPECT_EQ(obj, parser.getDom());
}

TEST(TestManifest, TestPublic)
{
    std::string id = "com.webos.app.any";
    std::string any = manifests + "/any.manifest.json";

    SecurityData security;
    EXPECT_TRUE(security.AddManifest(any, manifests, nullptr));
    {
        auto role = security.roles.Lookup(id);
        ASSERT_TRUE(role);
        EXPECT_EQ(LSHubRoleAllowedNamesDump(role), R"("com.webos.app.any")");

        validate(security, id.c_str(), "com.webos.app.any", pbnjson::JArray{"a", "b"}, pbnjson::JObject{});
    }
}

TEST(TestManifest, TestPublicOverlapped)
{
    std::string id = manifests + "/usr/bin/test";
    std::string v1 = manifests + "/v1.manifest.json";
    std::string v2 = manifests + "/v2.manifest.json";

    SecurityData security;
    EXPECT_TRUE(security.AddManifest(v1, manifests, nullptr));
    {
        auto role = security.roles.Lookup(id);
        ASSERT_TRUE(role);
        EXPECT_EQ(LSHubRoleAllowedNamesDump(role), R"("com.webos.service.test.a")");

        validate(security, id.c_str(), "com.webos.service.test.a",
                 pbnjson::JArray{"a"}, pbnjson::JObject{{"/a", pbnjson::JArray{"a"}}});
    }

    EXPECT_TRUE(security.AddManifest(v2, manifests, nullptr));
    {
        auto role = security.roles.Lookup(id);
        ASSERT_TRUE(role);
        EXPECT_EQ(LSHubRoleAllowedNamesDump(role), R"("com.webos.service.test.a", "com.webos.service.test.b")");

        validate(security, id.c_str(), "com.webos.service.test.a",
                 pbnjson::JArray{"a", "b"}, pbnjson::JObject{{"/a", pbnjson::JArray{"a"}}});
        validate(security, id.c_str(), "com.webos.service.test.b",
                 pbnjson::JArray{"b"}, pbnjson::JObject{{"/b", pbnjson::JArray{"b"}}});
    }

     security.RemoveManifest(v2);
     {
         auto role = security.roles.Lookup(id);
         ASSERT_TRUE(role);
         EXPECT_EQ(LSHubRoleAllowedNamesDump(role), R"("com.webos.service.test.a")");

         validate(security, id.c_str(), "com.webos.service.test.a",
                  pbnjson::JArray{"a"}, pbnjson::JObject{{"/a", pbnjson::JArray{"a"}}});
     }
}

TEST(TestManifest, TestManifestQueue)
{
    Manifest v1("v1", SemanticVersion("1.0.0"));
    Manifest v2("v2", SemanticVersion("2.0.0"));
    Manifest v3("v3", SemanticVersion("3.0.0"));
    Manifest v4("v4", SemanticVersion("4.0.0"));

    ManifestPriorityQueue queue;
    queue.push(&v1);
    queue.push(&v2);
    queue.push(&v3);
    queue.push(&v4);
    EXPECT_TRUE(queue.top() == &v4);

    queue.remove(&v3);
    EXPECT_TRUE(queue.top() == &v4);

    queue.remove(&v4);
    EXPECT_TRUE(queue.top() == &v2);

    queue.remove(&v2);
    EXPECT_TRUE(queue.top() == &v1);

    queue.remove(&v1);
    EXPECT_TRUE(queue.top() == nullptr);
}
