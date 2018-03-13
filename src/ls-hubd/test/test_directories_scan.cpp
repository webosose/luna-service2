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

#include <stdlib.h>
#include <string.h>
#include <gtest/gtest.h>
#include <unistd.h>

#include "test_util.hpp"
#include "test_security_util.hpp"

#include "../hub.hpp"
#include "../conf.hpp"
#include "../role_map.hpp"
#include "../security.hpp"
#include "../groups_map.hpp"
#include "../file_parser.hpp"
#include "../permissions_map.hpp"
#include "../patternqueue.hpp"

namespace {

bool LoadManifest(const std::vector<std::string>& dirs, const char *type)
{
    pbnjson::JArray files;
    for (const auto& item : dirs)
    {
        FileCollector collector;

        // load services from steady directories
        ProcessDirectory(item.c_str(), &collector, nullptr);
        for (const auto& f : collector.Files()) files << f;
    }

    pbnjson::JObject manifest;
    manifest.put(type, files);

    ManifestData data;
    if (!ManifestData::ProcessManifest(manifest, std::string(), data, nullptr))
        return false;

    SecurityData::CurrentSecurityData().LoadManifestData(std::move(data));
    return true;
}

} // anonymous namespace

TEST(TestDirectoriesScan, ScanServiceDirectories)
{
    EXPECT_TRUE(LoadManifest({steady_services}, "serviceFiles"));

    {
        ServiceMap &smap = SecurityData::CurrentSecurityData().services;
        EXPECT_TRUE(smap.Lookup("steady.service1") != NULL);
        EXPECT_TRUE(smap.Lookup("steady.service2") != NULL);
        EXPECT_TRUE(smap.Lookup("steady.service3_") != NULL);
        EXPECT_TRUE(smap.Lookup("steady.service4_") != NULL);
        EXPECT_TRUE(smap.Lookup("volatile.service1") == NULL);
        EXPECT_TRUE(smap.Lookup("volatile.service2") == NULL);
        EXPECT_TRUE(smap.Lookup("volatile.service3_") == NULL);
        EXPECT_TRUE(smap.Lookup("volatile.service4_") == NULL);
    }

    SecurityData::CurrentSecurityData() = SecurityData();
    LoadManifest({steady_services, volatile_services}, "serviceFiles");

    {
        ServiceMap &smap = SecurityData::CurrentSecurityData().services;
        EXPECT_TRUE(smap.Lookup("steady.service1") != NULL);
        EXPECT_TRUE(smap.Lookup("steady.service2") != NULL);
        EXPECT_TRUE(smap.Lookup("steady.service3_") != NULL);
        EXPECT_TRUE(smap.Lookup("steady.service4_") != NULL);
        EXPECT_TRUE(smap.Lookup("volatile.service1") != NULL);
        EXPECT_TRUE(smap.Lookup("volatile.service2") != NULL);
        EXPECT_TRUE(smap.Lookup("volatile.service3_") != NULL);
        EXPECT_TRUE(smap.Lookup("volatile.service4_") != NULL);
    }

    // remove all services
    SecurityData::CurrentSecurityData() = SecurityData();
    {
        ServiceMap &smap = SecurityData::CurrentSecurityData().services;
        EXPECT_TRUE(smap.Lookup("steady.service1") == NULL);
        EXPECT_TRUE(smap.Lookup("steady.service2") == NULL);
        EXPECT_TRUE(smap.Lookup("steady.service3_") == NULL);
        EXPECT_TRUE(smap.Lookup("steady.service4_") == NULL);
        EXPECT_TRUE(smap.Lookup("volatile.service1") == NULL);
        EXPECT_TRUE(smap.Lookup("volatile.service2") == NULL);
        EXPECT_TRUE(smap.Lookup("volatile.service3_") == NULL);
        EXPECT_TRUE(smap.Lookup("volatile.service4_") == NULL);
    }
}

TEST(TestDirectoriesScan, ScanRolesDirectoriesOldFormat)
{
    // scan roles from steady directories
    EXPECT_TRUE(LoadManifest({steady_roles_old}, "roleFilesPub"));

    {
        RoleMap &rmap = SecurityData::CurrentSecurityData().roles;

        EXPECT_TRUE(rmap.Lookup("/bin/foo") != NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/foo1") != NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/bar") != NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/steady.app1") != NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/steady.app2") != NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/volatile.app1") == NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/volatile.app2") == NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/volatile.app3") == NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/volatile.app4") == NULL);
        EXPECT_TRUE(rmap.Lookup("com.palm.app.volatile.id-1") == NULL);
    }

    {
        PermissionsMap &pmap = SecurityData::CurrentSecurityData().permissions;

        EXPECT_TRUE(pmap.Lookup("com.webos.foo", NULL) != NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.foo", "/bin/foo") != NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.foo", "/bin/default") != NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.foo1", NULL) != NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.foo1", "/bin/foo1") != NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.foo1", "/bin/default") != NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.bar1", NULL) != NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.bar1", "/bin/bar") != NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.bar1", "/bin/default") != NULL);
        EXPECT_TRUE(pmap.Lookup("steady.app1", NULL) != NULL);
        EXPECT_TRUE(pmap.Lookup("steady.app1", "/bin/steady.app1") != NULL);
        EXPECT_TRUE(pmap.Lookup("steady.app1", "/bin/default") != NULL);
        EXPECT_TRUE(pmap.Lookup("steady.app2", NULL) != NULL);
        EXPECT_TRUE(pmap.Lookup("steady.app2", "/bin/steady.app2") != NULL);
        EXPECT_TRUE(pmap.Lookup("steady.app2", "/bin/default") != NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app1", NULL) == NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app1", "/bin/volatile.app1") == NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app1", "/bin/default") == NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app2", NULL) == NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app2", "/bin/volatile.app2") == NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app2", "/bin/default") == NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app3", NULL) == NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app3", "/bin/volatile.app3") == NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app3", "/bin/default") == NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app4", NULL) == NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app4", "/bin/volatile.app4") == NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app4", "/bin/default") == NULL);
        EXPECT_TRUE(pmap.Lookup("com.palm.app.volatile.id-1", NULL) == NULL);
        EXPECT_TRUE(pmap.Lookup("com.palm.app.volatile.id-1", "com.palm.app.volatile.id") == NULL);
        EXPECT_TRUE(pmap.Lookup("com.palm.app.volatile.id-1", "/bin/default") == NULL);
    }

    // scan roles from volatile directories
    SecurityData::CurrentSecurityData() = SecurityData();
    EXPECT_TRUE(LoadManifest({steady_roles_old, volatile_roles_old}, "roleFilesPub"));

    {
        RoleMap &rmap = SecurityData::CurrentSecurityData().roles;

        EXPECT_TRUE(rmap.Lookup("/bin/foo") != NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/foo1") != NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/bar") != NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/steady.app1") != NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/steady.app2") != NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/volatile.app1") != NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/volatile.app2") != NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/volatile.app3") != NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/volatile.app4") != NULL);
    }

    {
        PermissionsMap &pmap = SecurityData::CurrentSecurityData().permissions;

        EXPECT_TRUE(pmap.Lookup("com.webos.foo", NULL) != NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.foo", "/bin/foo") != NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.foo", "/bin/default") != NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.foo1", NULL) != NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.foo1", "/bin/foo1") != NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.foo1", "/bin/default") != NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.bar1", NULL) != NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.bar1", "/bin/bar") != NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.bar1", "/bin/default") != NULL);
        EXPECT_TRUE(pmap.Lookup("steady.app1", NULL) != NULL);
        EXPECT_TRUE(pmap.Lookup("steady.app1", "/bin/steady.app1") != NULL);
        EXPECT_TRUE(pmap.Lookup("steady.app1", "/bin/default") != NULL);
        EXPECT_TRUE(pmap.Lookup("steady.app2", NULL) != NULL);
        EXPECT_TRUE(pmap.Lookup("steady.app2", "/bin/steady.app2") != NULL);
        EXPECT_TRUE(pmap.Lookup("steady.app2", "/bin/default") != NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app1", NULL) != NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app1", "/bin/volatile.app1") != NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app1", "/bin/default") != NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app2", NULL) != NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app2", "/bin/volatile.app2") != NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app2", "/bin/default") != NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app3", NULL) != NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app3", "/bin/volatile.app3") != NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app3", "/bin/default") != NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app4", NULL) != NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app4", "/bin/volatile.app4") != NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app4", "/bin/default") != NULL);
    }

    // reset all security data
    SecurityData::CurrentSecurityData() = SecurityData();
    {
        RoleMap &rmap = SecurityData::CurrentSecurityData().roles;

        EXPECT_TRUE(rmap.Lookup("/bin/foo") == NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/foo1") == NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/bar") == NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/steady.app1") == NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/steady.app2") == NULL);
        EXPECT_TRUE(rmap.Lookup("com.palm.app.steady.id") == NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/volatile.app1") == NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/volatile.app2") == NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/volatile.app3") == NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/volatile.app4") == NULL);
        EXPECT_TRUE(rmap.Lookup("com.palm.app.volatile.id") == NULL);
    }

    {
        PermissionsMap &pmap = SecurityData::CurrentSecurityData().permissions;

        EXPECT_TRUE(pmap.Lookup("com.webos.foo", NULL) == NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.foo", "/bin/foo") == NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.foo", "/bin/default") == NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.foo1", NULL) == NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.foo1", "/bin/foo1") == NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.foo1", "/bin/default") == NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.bar1", NULL) == NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.bar1", "/bin/bar") == NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.bar1", "/bin/default") == NULL);
        EXPECT_TRUE(pmap.Lookup("steady.app1", NULL) == NULL);
        EXPECT_TRUE(pmap.Lookup("steady.app1", "/bin/steady.app1") == NULL);
        EXPECT_TRUE(pmap.Lookup("steady.app1", "/bin/default") == NULL);
        EXPECT_TRUE(pmap.Lookup("steady.app2", NULL) == NULL);
        EXPECT_TRUE(pmap.Lookup("steady.app2", "/bin/steady.app2") == NULL);
        EXPECT_TRUE(pmap.Lookup("steady.app2", "/bin/default") == NULL);
        EXPECT_TRUE(pmap.Lookup("com.palm.app.steady.id-1", NULL) == NULL);
        EXPECT_TRUE(pmap.Lookup("com.palm.app.steady.id-1", "com.palm.app.steady.id") == NULL);
        EXPECT_TRUE(pmap.Lookup("com.palm.app.steady.id-1", "/bin/default") == NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app1", NULL) == NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app1", "/bin/volatile.app1") == NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app1", "/bin/default") == NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app2", NULL) == NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app2", "/bin/volatile.app2") == NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app2", "/bin/default") == NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app3", NULL) == NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app3", "/bin/volatile.app3") == NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app3", "/bin/default") == NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app4", NULL) == NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app4", "/bin/volatile.app4") == NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app4", "/bin/default") == NULL);
        EXPECT_TRUE(pmap.Lookup("com.palm.app.volatile.id-1", NULL) == NULL);
        EXPECT_TRUE(pmap.Lookup("com.palm.app.volatile.id-1", "com.palm.app.volatile.id") == NULL);
        EXPECT_TRUE(pmap.Lookup("com.palm.app.volatile.id-1", "/bin/default") == NULL);
    }
}

TEST(TestDirectoriesScan, ScanRolesDirectories)
{
    // scan roles from steady directories
    EXPECT_TRUE(LoadManifest({steady_roles}, "roleFiles"));

    {
        RoleMap &rmap = SecurityData::CurrentSecurityData().roles;

        EXPECT_TRUE(rmap.Lookup("/bin/foo") != NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/foo1") != NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/bar") != NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/steady.app1") != NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/steady.app2") != NULL);
        EXPECT_TRUE(rmap.Lookup("com.palm.app.steady.id") != NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/volatile.app1") == NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/volatile.app2") == NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/volatile.app3") == NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/volatile.app4") == NULL);
        EXPECT_TRUE(rmap.Lookup("com.palm.app.volatile.id") == NULL);
    }

    {
        PermissionsMap &pmap = SecurityData::CurrentSecurityData().permissions;

        EXPECT_TRUE(pmap.Lookup("com.webos.foo", NULL) != NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.foo", "/bin/foo") != NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.foo", "/bin/default") != NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.foo1", NULL) != NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.foo1", "/bin/foo1") != NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.foo1", "/bin/default") != NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.bar1", NULL) != NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.bar1", "/bin/bar") != NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.bar1", "/bin/default") != NULL);
        EXPECT_TRUE(pmap.Lookup("steady.app1", NULL) != NULL);
        EXPECT_TRUE(pmap.Lookup("steady.app1", "/bin/steady.app1") != NULL);
        EXPECT_TRUE(pmap.Lookup("steady.app1", "/bin/default") != NULL);
        EXPECT_TRUE(pmap.Lookup("steady.app2", NULL) != NULL);
        EXPECT_TRUE(pmap.Lookup("steady.app2", "/bin/steady.app2") != NULL);
        EXPECT_TRUE(pmap.Lookup("steady.app2", "/bin/default") != NULL);
        EXPECT_TRUE(pmap.Lookup("com.palm.app.steady.id-1", NULL) != NULL);
        EXPECT_TRUE(pmap.Lookup("com.palm.app.steady.id-1", "com.palm.app.steady.id") != NULL);
        EXPECT_TRUE(pmap.Lookup("com.palm.app.steady.id-1", "/bin/default") != NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app1", NULL) == NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app1", "/bin/volatile.app1") == NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app1", "/bin/default") == NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app2", NULL) == NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app2", "/bin/volatile.app2") == NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app2", "/bin/default") == NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app3", NULL) == NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app3", "/bin/volatile.app3") == NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app3", "/bin/default") == NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app4", NULL) == NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app4", "/bin/volatile.app4") == NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app4", "/bin/default") == NULL);

        EXPECT_TRUE(pmap.Lookup("com.palm.app.volatile.id-1", NULL) == NULL);
        EXPECT_TRUE(pmap.Lookup("com.palm.app.volatile.id-1", "com.palm.app.volatile.id") == NULL);
        EXPECT_TRUE(pmap.Lookup("com.palm.app.volatile.id-1", "/bin/default") == NULL);
    }

    SecurityData::CurrentSecurityData() = SecurityData();
    LoadManifest({steady_roles, volatile_roles}, "roleFiles");

    {
        RoleMap &rmap = SecurityData::CurrentSecurityData().roles;

        EXPECT_TRUE(rmap.Lookup("/bin/foo") != NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/foo1") != NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/bar") != NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/steady.app1") != NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/steady.app2") != NULL);
        EXPECT_TRUE(rmap.Lookup("com.palm.app.steady.id") != NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/volatile.app1") != NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/volatile.app2") != NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/volatile.app3") != NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/volatile.app4") != NULL);
        EXPECT_TRUE(rmap.Lookup("com.palm.app.volatile.id") != NULL);
    }

    {
        PermissionsMap &pmap = SecurityData::CurrentSecurityData().permissions;

        EXPECT_TRUE(pmap.Lookup("com.webos.foo", NULL) != NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.foo", "/bin/foo") != NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.foo", "/bin/default") != NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.foo1", NULL) != NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.foo1", "/bin/foo1") != NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.foo1", "/bin/default") != NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.bar1", NULL) != NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.bar1", "/bin/bar") != NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.bar1", "/bin/default") != NULL);
        EXPECT_TRUE(pmap.Lookup("steady.app1", NULL) != NULL);
        EXPECT_TRUE(pmap.Lookup("steady.app1", "/bin/steady.app1") != NULL);
        EXPECT_TRUE(pmap.Lookup("steady.app1", "/bin/default") != NULL);
        EXPECT_TRUE(pmap.Lookup("steady.app2", NULL) != NULL);
        EXPECT_TRUE(pmap.Lookup("steady.app2", "/bin/steady.app2") != NULL);
        EXPECT_TRUE(pmap.Lookup("steady.app2", "/bin/default") != NULL);
        EXPECT_TRUE(pmap.Lookup("com.palm.app.steady.id-1", NULL) != NULL);
        EXPECT_TRUE(pmap.Lookup("com.palm.app.steady.id-1", "com.palm.app.steady.id") != NULL);
        EXPECT_TRUE(pmap.Lookup("com.palm.app.steady.id-1", "/bin/default") != NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app1", NULL) != NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app1", "/bin/volatile.app1") != NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app1", "/bin/default") != NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app2", NULL) != NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app2", "/bin/volatile.app2") != NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app2", "/bin/default") != NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app3", NULL) != NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app3", "/bin/volatile.app3") != NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app3", "/bin/default") != NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app4", NULL) != NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app4", "/bin/volatile.app4") != NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app4", "/bin/default") != NULL);
        EXPECT_TRUE(pmap.Lookup("com.palm.app.volatile.id-1", NULL) != NULL);
        EXPECT_TRUE(pmap.Lookup("com.palm.app.volatile.id-1", "com.palm.app.volatile.id") != NULL);
        EXPECT_TRUE(pmap.Lookup("com.palm.app.volatile.id-1", "/bin/default") != NULL);
    }

    // reset all security data
    SecurityData::CurrentSecurityData() = SecurityData();

    {
        RoleMap &rmap = SecurityData::CurrentSecurityData().roles;

        EXPECT_TRUE(rmap.Lookup("/bin/foo") == NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/foo1") == NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/bar") == NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/steady.app1") == NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/steady.app2") == NULL);
        EXPECT_TRUE(rmap.Lookup("com.palm.app.steady.id") == NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/volatile.app1") == NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/volatile.app2") == NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/volatile.app3") == NULL);
        EXPECT_TRUE(rmap.Lookup("/bin/volatile.app4") == NULL);
        EXPECT_TRUE(rmap.Lookup("com.palm.app.volatile.id") == NULL);
    }

    {
        PermissionsMap &pmap = SecurityData::CurrentSecurityData().permissions;

        EXPECT_TRUE(pmap.Lookup("com.webos.foo", NULL) == NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.foo", "/bin/foo") == NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.foo", "/bin/default") == NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.foo1", NULL) == NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.foo1", "/bin/foo1") == NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.foo1", "/bin/default") == NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.bar1", NULL) == NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.bar1", "/bin/bar") == NULL);
        EXPECT_TRUE(pmap.Lookup("com.webos.bar1", "/bin/default") == NULL);
        EXPECT_TRUE(pmap.Lookup("steady.app1", NULL) == NULL);
        EXPECT_TRUE(pmap.Lookup("steady.app1", "/bin/steady.app1") == NULL);
        EXPECT_TRUE(pmap.Lookup("steady.app1", "/bin/default") == NULL);
        EXPECT_TRUE(pmap.Lookup("steady.app2", NULL) == NULL);
        EXPECT_TRUE(pmap.Lookup("steady.app2", "/bin/steady.app2") == NULL);
        EXPECT_TRUE(pmap.Lookup("steady.app2", "/bin/default") == NULL);
        EXPECT_TRUE(pmap.Lookup("com.palm.app.steady.id-1", NULL) == NULL);
        EXPECT_TRUE(pmap.Lookup("com.palm.app.steady.id-1", "com.palm.app.steady.id") == NULL);
        EXPECT_TRUE(pmap.Lookup("com.palm.app.steady.id-1", "/bin/default") == NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app1", NULL) == NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app1", "/bin/volatile.app1") == NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app1", "/bin/default") == NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app2", NULL) == NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app2", "/bin/volatile.app2") == NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app2", "/bin/default") == NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app3", NULL) == NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app3", "/bin/volatile.app3") == NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app3", "/bin/default") == NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app4", NULL) == NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app4", "/bin/volatile.app4") == NULL);
        EXPECT_TRUE(pmap.Lookup("volatile.app4", "/bin/default") == NULL);
        EXPECT_TRUE(pmap.Lookup("com.palm.app.volatile.id-1", NULL) == NULL);
        EXPECT_TRUE(pmap.Lookup("com.palm.app.volatile.id-1", "com.palm.app.volatile.id") == NULL);
        EXPECT_TRUE(pmap.Lookup("com.palm.app.volatile.id-1", "/bin/default") == NULL);
    }
}

TEST(TestDirectoriesScan, ScanMalformedRoles)
{
    // not correct
    pbnjson::JArray _1;
    _1 << malformed_roles + "/ambiguous.json";
    _1 << malformed_roles + "/malformed1.json";
    _1 << malformed_roles + "/malformed4.json";
    _1 << malformed_roles + "/malformed6.json";

    // partially correct
    pbnjson::JArray _2;
    _2 << malformed_roles + "/malformed2.json";
    _2 << malformed_roles + "/malformed3.json";
    _2 << malformed_roles + "/malformed5.json";

    ManifestData data;
    EXPECT_FALSE(ManifestData::ProcessManifest(pbnjson::JObject{{"roleFiles", _1}}, std::string(), data, nullptr));

    data = std::move(ManifestData());
#ifdef LS_VALIDATE_CONF
    EXPECT_FALSE(ManifestData::ProcessManifest(pbnjson::JObject{{"roleFiles", _2}}, std::string(), data, nullptr));
#else
    EXPECT_TRUE(ManifestData::ProcessManifest(pbnjson::JObject{{"roleFiles", _2}}, std::string(), data, nullptr));
#endif

    SecurityData::CurrentSecurityData().LoadManifestData(std::move(data));

    RoleMap &rmap = SecurityData::CurrentSecurityData().roles;
    PermissionsMap &pmap = SecurityData::CurrentSecurityData().permissions;

    // test malformed JSON role files
#ifdef LS_VALIDATE_CONF
    // absence of allowed names will render whole role invalid
    EXPECT_TRUE(rmap.Lookup("/bin/malformed2") == NULL);
    EXPECT_TRUE(pmap.Lookup("com.webos.malformed2", NULL) == NULL);

    // no permissions
    EXPECT_TRUE(rmap.Lookup("/bin/malformed3") == NULL);

    // allowedNames isn't an array
    EXPECT_TRUE(rmap.Lookup("/bin/malformed5") == NULL);
    EXPECT_TRUE(pmap.Lookup("com.webos.malformed5", NULL) == NULL);
#else
    // absence of allowed names isn't so critical
    ASSERT_TRUE(rmap.Lookup("/bin/malformed2"));
    EXPECT_TRUE(_LSHubPatternQueueIsEmpty(rmap.Lookup("/bin/malformed2")->allowed_names));

    // We still can register without permissions but there will be no permissions
    EXPECT_TRUE(rmap.Lookup("/bin/malformed3"));

    // allowedNames isn't an array but we'll treat as an empty array
    ASSERT_TRUE(rmap.Lookup("/bin/malformed5"));
    EXPECT_TRUE(_LSHubPatternQueueIsEmpty(rmap.Lookup("/bin/malformed5")->allowed_names));
    EXPECT_TRUE(pmap.Lookup("com.webos.malformed5", NULL));
#endif

    EXPECT_TRUE(rmap.Lookup("/bin/malformed1") == NULL);
    EXPECT_TRUE(rmap.Lookup("/bin/malformed4") == NULL);
    EXPECT_TRUE(rmap.Lookup("com.palm.app.malformed") == NULL);
    EXPECT_TRUE(rmap.Lookup("/bin/ambiguous") == NULL);
    EXPECT_TRUE(rmap.Lookup("com.palm.app.ambiguous") == NULL);
    EXPECT_TRUE(pmap.Lookup("com.webos.malformed1", NULL) == NULL);
    EXPECT_TRUE(pmap.Lookup("com.webos.malformed3", NULL) == NULL);
    EXPECT_TRUE(pmap.Lookup("com.webos.malformed4", NULL) == NULL);
    EXPECT_TRUE(pmap.Lookup("com.palm.app.malformed", NULL) == NULL);
    EXPECT_TRUE(pmap.Lookup("com.palm.app.ambiguous", NULL) == NULL);
}

TEST(TestDirectoriesScan, ScanContainersDirectories)
{
    LSError lserror;
    LSErrorInit(&lserror);

    // scan containers definitions from test directories
    SecurityData sdata;
    const char *dirs[] = {containers_dir.c_str(), nullptr};
    ASSERT_TRUE(ProcessContainersDirectories(dirs, &sdata, &lserror));
    SecurityData::CurrentSecurityData() = std::move(sdata);

    EXPECT_TRUE(LSHubAppContainersGet().size() == 3);
    EXPECT_TRUE(_LSHubIsExeApplicationContainer("/usr/bin/QtWebProcess"));
    EXPECT_TRUE(_LSHubIsExeApplicationContainer("/usr/bin/node"));
    EXPECT_TRUE(!_LSHubIsExeApplicationContainer("/usr/bin/WebAppManager"));

    // reset all security data
    SecurityData::CurrentSecurityData() = SecurityData();
    EXPECT_TRUE(LSHubAppContainersGet().size() == 0);
    EXPECT_TRUE(!_LSHubIsExeApplicationContainer("/usr/bin/QtWebProcess"));

    LSErrorFree(&lserror);
}

TEST(TestDirectoriesScan, SHubScanPermissionsDirectories)
{
    EXPECT_TRUE(LoadManifest({permissions_dir}, "clientPermissionFiles"));

    Groups groups;

    const char *foo_str = g_intern_string("foo");
    const char *bar_str = g_intern_string("bar");
    const char *foobar_str = g_intern_string("foobar");
    const char *private_str = g_intern_string("private");
    const char *public_str = g_intern_string("public");
    const char *app_str = g_intern_string("app");
    const char *id_str = g_intern_string("id");

    {
        GroupsMap& sg = SecurityData::CurrentSecurityData().groups;
        groups = sg.GetRequired("com.webos.foo.1");
        EXPECT_EQ(Groups({foo_str}), groups);
        groups = sg.GetRequired("com.webos.bar");
        EXPECT_EQ(Groups({bar_str}), groups);
        EXPECT_TRUE(sg.GetRequired("com.webos.bar.1").empty());
        groups = sg.GetRequired("com.webos.all");
        EXPECT_EQ(Groups({foo_str, bar_str, private_str, foobar_str, public_str}), groups);
        groups = sg.GetRequired("com.webos.all.id");
        EXPECT_EQ(Groups({foobar_str, public_str}), groups);
        groups = sg.GetRequired("com.webos.app.1");
        EXPECT_EQ(Groups({app_str}), groups);
        groups = sg.GetRequired("com.webos.app.id.1");
        EXPECT_EQ(Groups({app_str, id_str}), groups);
    }

    // reset all security data
    SecurityData::CurrentSecurityData() = SecurityData();
    {
        GroupsMap& sg = SecurityData::CurrentSecurityData().groups;
        EXPECT_TRUE(sg.GetRequired("com.webos.foo.1").empty());
        EXPECT_TRUE(sg.GetRequired("com.webos.bar").empty());
        EXPECT_TRUE(sg.GetRequired("com.webos.bar.1").empty());
        EXPECT_TRUE(sg.GetRequired("com.webos.all").empty());
        EXPECT_TRUE(sg.GetRequired("com.webos.all.id").empty());
        EXPECT_TRUE(sg.GetRequired("com.webos.app.1").empty());
        EXPECT_TRUE(sg.GetRequired("com.webos.app.id.1").empty());
        EXPECT_TRUE(sg.GetRequired("com.webos.malformed").empty());
        EXPECT_TRUE(sg.GetRequired("com.webos.malformed.id").empty());
    }
}

TEST(TestDirectoriesScan, ScanMalformedPermissions)
{
    EXPECT_FALSE(LoadManifest({malformed_permissions}, "clientPermissionFiles"));

    GroupsMap& sg = SecurityData::CurrentSecurityData().groups;
    EXPECT_TRUE(sg.GetRequired("com.webos.malformed").empty());
    EXPECT_TRUE(sg.GetRequired("com.webos.malformed.id").empty());
}

int main(int argc, char *argv[])
{
    ConfigSetDefaults();

    ::testing::InitGoogleTest(&argc, argv);

    return RUN_ALL_TESTS();
}
