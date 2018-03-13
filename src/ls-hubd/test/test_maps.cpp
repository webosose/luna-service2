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

#include "../util.hpp"
#include "../role.hpp"
#include "../role_map.hpp"
#include "../permission.hpp"
#include "../groups_map.hpp"
#include "../service_map.hpp"
#include "../patternqueue.hpp"
#include "../permissions_map.hpp"
#include "../service_permissions.hpp"

static auto make = [](const char* name, const char* id, uint32_t flags, const std::vector<std::string>& io)
{
    auto ret = mk_ptr(LSHubPermissionNewRef(name, id), LSHubPermissionUnref);
    ret->perm_flags = flags;
    for (const auto& i : io) LSHubPermissionAddAllowedInbound(ret.get(), i.c_str());
    for (const auto& o : io) LSHubPermissionAddAllowedOutbound(ret.get(), o.c_str());
    return std::move(ret);
};

TEST(TestMaps, TestRoleMapAddRemove)
{
    RoleMap map;
    auto f = mk_ptr(LSHubRoleNewRef("first", LSHubRoleTypeRegular), LSHubRoleUnref);
    auto s = mk_ptr(LSHubRoleNewRef("second", LSHubRoleTypeRegular), LSHubRoleUnref);

    map.Add(std::move(f));
    map.Add(std::move(s));

    EXPECT_TRUE(map.Lookup("first"));
    EXPECT_TRUE(map.Lookup("second"));

    map.Remove("first");
    EXPECT_FALSE(map.Lookup("first"));

    map.Remove("second");
    EXPECT_FALSE(map.Lookup("second"));
}

TEST(TestMaps, TestRoleMapAddRemoveMerge)
{
    RoleMap map;

    auto r_public = mk_ptr(LSHubRoleNewRef("role", LSHubRoleTypeRegular), LSHubRoleUnref);
    r_public->role_flags = PUBLIC_BUS_ROLE;
    for (const auto &name : {"a", "b"}) LSHubRoleAddAllowedName(r_public.get(), name);

    map.Add(std::move(r_public));

    auto r_private = mk_ptr(LSHubRoleNewRef("role", LSHubRoleTypeRegular), LSHubRoleUnref);
    r_private->role_flags = PRIVATE_BUS_ROLE;
    for (const auto &name : {"c"}) LSHubRoleAddAllowedName(r_private.get(), name);

    map.Add(std::move(r_private));

    const LSHubRole *role = map.Lookup("role");
    EXPECT_TRUE(role);
    EXPECT_EQ(LSHubRoleAllowedNamesDump(role), R"("a", "b", "c")");

    map.Remove("role");

    EXPECT_FALSE(map.Lookup("role"));
}

TEST(TestMaps, TestPermissionsAddRemove)
{
    auto perms = mk_ptr(LSHubServicePermissionsNewRef("com.webos.service.foo"), LSHubServicePermissionsUnref);
    auto p = make("com.webos.service.foo", "/usr/bin/p", NO_BUS_ROLE, {"a", "b"});

    LSHubServicePermissionsAddPermissionRef(perms.get(), p.get());
    EXPECT_TRUE(LSHubServicePermissionsLookupPermission(perms.get(), p->exe_path));

    LSHubServicePermissionsUnrefPermission(perms.get(), p->exe_path);
    auto found = LSHubServicePermissionsLookupPermission(perms.get(), p->exe_path);

    EXPECT_EQ(found, perms->default_permission);
    EXPECT_EQ(_LSHubPatternQueueDump(found->inbound), R"([])");
    EXPECT_EQ(_LSHubPatternQueueDump(found->outbound), R"([])");
}

TEST(TestMaps, TestPermissionsAddRemoveMerge)
{
    auto perms = mk_ptr(LSHubServicePermissionsNewRef("com.webos.service.foo"), LSHubServicePermissionsUnref);

    auto p_public = make("com.webos.service.foo", "/usr/bin/p", PUBLIC_BUS_ROLE, {"a", "b"});
    auto p_private = make("com.webos.service.foo", "/usr/bin/p", PRIVATE_BUS_ROLE, {"a", "c"});

    LSHubServicePermissionsAddPermissionRef(perms.get(), p_public.get());

    // get defaults
    auto def = LSHubServicePermissionsLookupPermission(perms.get(), nullptr);
    EXPECT_EQ(def->perm_flags, PUBLIC_BUS_ROLE);

    LSHubServicePermissionsAddPermissionRef(perms.get(), p_private.get());

    // get updated defaults
    def = LSHubServicePermissionsLookupPermission(perms.get(), nullptr);
    EXPECT_EQ(def->perm_flags, PUBLIC_BUS_ROLE | PRIVATE_BUS_ROLE);

    LSHubPermission* perm = LSHubServicePermissionsLookupPermission(perms.get(), "/usr/bin/p");
    EXPECT_TRUE(perm);

    EXPECT_EQ(_LSHubPatternQueueDump(perm->inbound), R"(["a", "b", "c"])");
    EXPECT_EQ(_LSHubPatternQueueDump(perm->outbound), R"(["a", "b", "c"])");

    LSHubServicePermissionsUnrefPermission(perms.get(), "/usr/bin/p");
    auto found = LSHubServicePermissionsLookupPermission(perms.get(), "/usr/bin/p");

    EXPECT_EQ(found, perms->default_permission);
    EXPECT_EQ(_LSHubPatternQueueDump(found->inbound), R"([])");
    EXPECT_EQ(_LSHubPatternQueueDump(found->outbound), R"([])");
}

TEST(TestMaps, TestPermissionsAddRemoveDefault)
{
    auto perms = mk_ptr(LSHubServicePermissionsNewRef("com.webo.service.foo"), LSHubServicePermissionsUnref);
    auto p1 = make("com.webo.service.foo", "/usr/bin/p1", NO_BUS_ROLE, {"a", "b"});
    auto p2 = make("com.webo.service.foo", "/usr/bin/p2", NO_BUS_ROLE, {"a", "c"});

    LSHubServicePermissionsAddPermissionRef(perms.get(), p1.get());

    EXPECT_TRUE(LSHubServicePermissionsLookupPermission(perms.get(), p1->exe_path));
    EXPECT_EQ(_LSHubPatternQueueDump(perms->default_permission->inbound), R"(["a", "b"])");

    LSHubServicePermissionsAddPermissionRef(perms.get(), p2.get());

    EXPECT_TRUE(LSHubServicePermissionsLookupPermission(perms.get(), p2->exe_path));
    EXPECT_EQ(_LSHubPatternQueueDump(perms->default_permission->outbound), R"(["a", "a", "b", "c"])");

    LSHubServicePermissionsUnrefPermission(perms.get(), p1->exe_path);
    EXPECT_TRUE(LSHubServicePermissionsLookupPermission(perms.get(), p2->exe_path));

    auto found = LSHubServicePermissionsLookupPermission(perms.get(), p1->exe_path);
    EXPECT_EQ(found, perms->default_permission);
    EXPECT_EQ(_LSHubPatternQueueDump(found->inbound), R"(["a", "c"])");
    EXPECT_EQ(_LSHubPatternQueueDump(found->outbound), R"(["a", "c"])");

    LSHubServicePermissionsUnrefPermission(perms.get(), p2->exe_path);

    found = LSHubServicePermissionsLookupPermission(perms.get(), p2->exe_path);
    EXPECT_EQ(found, perms->default_permission);
    EXPECT_EQ(_LSHubPatternQueueDump(found->inbound), R"([])");
    EXPECT_EQ(_LSHubPatternQueueDump(found->outbound), R"([])");
}

TEST(TestMaps, TestPermissionsMapAddRemove)
{
    PermissionsMap map;

    auto p = mk_ptr(LSHubPermissionNewRef("com.webos.service.foo", "/usr/bin/foo"), LSHubPermissionUnref);

    map.Add(std::move(p));
    EXPECT_TRUE(map.Lookup("com.webos.service.foo", "/usr/bin/foo"));
    EXPECT_TRUE(map.LookupServicePermissions("com.webos.service.foo"));

    map.Remove("com.webos.service.foo", "/usr/bin/foo");
    EXPECT_FALSE(map.Lookup("com.webos.service.foo", "/usr/bin/foo"));
    EXPECT_FALSE(map.LookupServicePermissions("com.webos.service.foo"));
}

TEST(TestMaps, TestServiceMapAddRemove)
{
    ServiceMap map;

    const char* fnames[] = {"f"};
    const char* snames[] = {"s*"};
    auto f = mk_ptr(_ServiceNewRef(fnames, 1, "/usr/bin/f", true, "f.service"), _ServiceUnref);
    auto s = mk_ptr(_ServiceNewRef(snames, 1, "/usr/bin/s", true, "s.service"), _ServiceUnref);

    map.Add(std::move(f));
    map.Add(std::move(s));

    EXPECT_TRUE(map.Lookup("f"));
    EXPECT_TRUE(map.Lookup("s*"));

    map.Remove(fnames, 1);
    map.Remove(snames, 1);

    EXPECT_FALSE(map.Lookup("f"));
    EXPECT_FALSE(map.Lookup("s*"));
}

TEST(TestMaps, TestGrousMapAddRemoveProvided)
{
    const char *ffa = g_intern_string("foo.first.a");
    const char *ffb = g_intern_string("foo.first.b");
    const char *fsa = g_intern_string("foo.second.a");
    const char *fsb = g_intern_string("foo.second.b");

    const char *bfa = g_intern_string("bar.first.a");
    const char *bfb = g_intern_string("bar.first.b");
    const char *bsa = g_intern_string("bar.second.a");
    const char *bsb = g_intern_string("bar.second.b");

    GroupsMap map;
    map.AddProvided("com.webos.service.foo", "/first", ffa);
    map.AddProvided("com.webos.service.foo", "/first", ffb);
    map.AddProvided("com.webos.service.foo", "/second", fsa);
    map.AddProvided("com.webos.service.foo", "/second", fsb);

    map.AddProvided("com.webos.service.bar", "/first", bfa);
    map.AddProvided("com.webos.service.bar", "/first", bfb);
    map.AddProvided("com.webos.service.bar", "/second", bsa);
    map.AddProvided("com.webos.service.bar", "/second", bsb);

    {
        CategoryMap foo =
        {
            { "/first", { ffa, ffb } },
            { "/second", { fsa, fsb} }
        };
        EXPECT_EQ(map.GetProvided("com.webos.service.foo"), foo);

        CategoryMap bar =
        {
            { "/first", { bfa, bfb } },
            {"/second", { bsa, bsb } }
        };
        EXPECT_EQ(map.GetProvided("com.webos.service.bar"), bar);
    }

    map.RemoveProvided("com.webos.service.foo", "/first", "foo.first.a");
    map.RemoveProvided("com.webos.service.bar", "/second", "bar.second.b");

    {
        CategoryMap foo =
        {
            {"/first", { ffb } },
            {"/second", { fsa, fsb } }
        };
        EXPECT_EQ(map.GetProvided("com.webos.service.foo"), foo);

        CategoryMap bar =
        {
            {"/first", { bfa, bfb } },
            {"/second", { bsa } }
        };
        EXPECT_EQ(map.GetProvided("com.webos.service.bar"), bar);
    }

    map.RemoveProvided("com.webos.service.foo", "/first", ffb);
    map.RemoveProvided("com.webos.service.foo", "/second", fsa);
    map.RemoveProvided("com.webos.service.bar", "/first", bfb);
    map.RemoveProvided("com.webos.service.bar", "/second", bsa);

    {
        CategoryMap foo = map.GetProvided("com.webos.service.foo");
        EXPECT_TRUE(foo.find("/first") == foo.end());

        Groups second = { fsb };
        EXPECT_EQ(foo["/second"], second);

        CategoryMap bar = map.GetProvided("com.webos.service.bar");
        EXPECT_TRUE(bar.find("/second") == bar.end());

        Groups first = { bfa };
        EXPECT_EQ(bar["/first"], first);
    }

    map.RemoveProvided("com.webos.service.foo", "/second", fsb);
    map.RemoveProvided("com.webos.service.bar", "/first", bfa);

    {
        CategoryMap foo = map.GetProvided("com.webos.service.foo");
        EXPECT_TRUE(foo.find("/first") == foo.end());
        EXPECT_TRUE(foo.find("/second") == foo.end());

        CategoryMap bar = map.GetProvided("com.webos.service.bar");
        EXPECT_TRUE(bar.find("/first") == bar.end());
        EXPECT_TRUE(bar.find("/second") == bar.end());
    }
}

TEST(TestMaps, TestGrousMapAddRemoveRequired)
{
    const char *fa = g_intern_string("foo.a");
    const char *fb = g_intern_string("foo.b");

    const char *ba = g_intern_string("bar.a");
    const char *bb = g_intern_string("bar.b");

    GroupsMap map;
    map.AddRequired("com.webos.service.foo", fa);
    map.AddRequired("com.webos.service.foo", fb);

    map.AddRequired("com.webos.service.bar", ba);
    map.AddRequired("com.webos.service.bar", bb);

    {
        Groups foo = { fa, fb };
        EXPECT_EQ(map.GetRequired("com.webos.service.foo"), foo);

        Groups bar = { ba, bb };
        EXPECT_EQ(map.GetRequired("com.webos.service.bar"), bar);
    }

    map.RemoveRequired("com.webos.service.foo", fa);
    map.RemoveRequired("com.webos.service.bar", bb);

    {
        Groups foo = { fb };
        EXPECT_EQ(map.GetRequired("com.webos.service.foo"), foo);

        Groups bar = { ba };
        EXPECT_EQ(map.GetRequired("com.webos.service.bar"), bar);
    }

    map.RemoveRequired("com.webos.service.foo", fb);
    map.RemoveRequired("com.webos.service.bar", ba);

    {
        Groups foo = map.GetRequired("com.webos.service.foo");
        EXPECT_TRUE(foo.empty());

        Groups bar = map.GetRequired("com.webos.service.foo");
        EXPECT_TRUE(bar.empty());
    }
}

TEST(TestMaps, TestGrousMapAddRemoveOverlapped)
{
    const char *a = g_intern_string("a");
    const char *b = g_intern_string("b");

    GroupsMap map;
    map.AddProvided("com.webos.service.foo", "/", a);
    map.AddProvided("com.webos.service.foo", "/", b);
    map.AddProvided("com.webos.service.bar", "/", a);

    {
        CategoryMap foo =
        {
            { "/", { a, b } }
        };
        EXPECT_EQ(map.GetProvided("com.webos.service.foo"), foo);

        CategoryMap bar =
        {
            { "/", { a }  }
        };
        EXPECT_EQ(map.GetProvided("com.webos.service.bar"), bar);
    }

    map.RemoveProvided("com.webos.service.foo", "/", a);
    map.RemoveProvided("com.webos.service.foo", "/", b);

    {
        EXPECT_TRUE(map.GetProvided("com.webos.service.foo").empty());

        CategoryMap bar =
        {
            {"/", { a } }
        };
        EXPECT_EQ(map.GetProvided("com.webos.service.bar"), bar);
    }

    map.RemoveProvided("com.webos.service.bar", "/", a);

    {
        EXPECT_TRUE(map.GetProvided("com.webos.service.foo").empty());
        EXPECT_TRUE(map.GetProvided("com.webos.service.bar").empty());
    }
}

