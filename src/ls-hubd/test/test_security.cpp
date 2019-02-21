// Copyright (c) 2014-2019 LG Electronics, Inc.
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

#include <string>
#include <cstdlib>

#include <unistd.h>

#include <glib.h>
#include <pbnjson.hpp>

#include "test_util.hpp"
#include "test_security_util.hpp"

#include "../conf.hpp"
#include "../security.hpp"
#include "../manifest.hpp"
#include "../permission.hpp"
#include "../file_parser.hpp"
#include "../active_role_map.hpp"
#include "../active_permission_map.hpp"
#include "../../libluna-service2/transport.h"


void ConfigSetDefaults(void);
void _ConfigFreeSettings(void);

typedef struct TestData {
} TestData;

static void
test_LSHubPermissionMapLookupOldFormat(TestData *fixture, gconstpointer user_data)
{
    ConfigSetDefaults();

    int32_t service_flags = _LSTransportFlagNoFlags;
    SecurityData sdata;
    FileCollector collector;

    ProcessDirectory(steady_roles_old.c_str(), &collector, nullptr);

    pbnjson::JArray files;
    for (const auto& f : collector.Files()) files << f;

    pbnjson::JObject manifest;
    manifest.put("roleFilesPub", files);

    ManifestData data;
    ManifestData::ProcessManifest(manifest, std::string(), data, nullptr);
    sdata.LoadManifestData(std::move(data));

    SecurityData::CurrentSecurityData() = std::move(sdata);

    pid_t sender_pid = getpid();
    pid_t dest_pid = sender_pid + 1;
    struct LSTransportHandlers test_handlers = {};

    _LSTransportCred *sender_cred = _LSTransportCredNew();
    g_assert(sender_cred);
    _LSTransportCredSetPid(sender_cred, sender_pid);
    _LSTransport *sender_transport = NULL;
    g_assert(_LSTransportInit(&sender_transport, "com.webos.foo", nullptr, &test_handlers, NULL));

    _LSTransportClient sender_client = {};
    sender_client.service_name = const_cast<char*>("com.webos.foo");
    sender_client.cred = sender_cred;
    sender_client.transport = sender_transport;

    _LSTransportCred *dest_cred = _LSTransportCredNew();
    g_assert(dest_cred);
    _LSTransportCredSetPid(dest_cred, dest_pid);
    _LSTransport *dest_transport = NULL;
    g_assert(_LSTransportInit(&dest_transport, "com.webos.bar", nullptr, &test_handlers, NULL));

    _LSTransportClient dest_client = {};
    dest_client.service_name = const_cast<char*>("com.webos.bar");
    dest_client.cred = dest_cred;
    dest_client.transport = dest_transport;

    _LSTransportCredSetExePath(sender_cred, "/bin/foo");
    sender_client.service_name = const_cast<char*>("com.webos.foo");
    g_assert(LSHubIsClientAllowedToRequestName(&sender_client, "com.webos.foo", service_flags));
    g_assert(service_flags & _LSTransportFlagOldConfig);
    service_flags = _LSTransportFlagNoFlags;
    LSHubActiveRoleMapUnref(sender_pid);
    g_assert(!LSHubIsClientAllowedToRequestName(&sender_client, "com.webos.foo2", service_flags));
    g_assert(service_flags == _LSTransportFlagNoFlags);
    service_flags = _LSTransportFlagNoFlags;
    LSHubActiveRoleMapUnref(sender_pid);

    _LSTransportCredSetExePath(sender_cred, "/bin/bar");
    sender_client.service_name = const_cast<char*>("com.webos.bar");
    g_assert(LSHubIsClientAllowedToRequestName(&sender_client, "com.webos.bar", service_flags));
    g_assert(service_flags & _LSTransportFlagOldConfig);
    service_flags = _LSTransportFlagNoFlags;
    LSHubActiveRoleMapUnref(sender_pid);
    g_assert(LSHubIsClientAllowedToRequestName(&sender_client, "com.webos.bar2", service_flags));
    g_assert(service_flags & _LSTransportFlagOldConfig);
    service_flags = _LSTransportFlagNoFlags;
    LSHubActiveRoleMapUnref(sender_pid);

    _LSTransportCredSetExePath(sender_cred, "/bin/foo");
    sender_client.service_name = const_cast<char*>("com.webos.foo");
    g_assert(LSHubIsClientAllowedToQueryName(&sender_client, NULL, "com.webos.bar"));
    _LSTransportCredSetExePath(sender_cred, "/bin/bar");
    sender_client.service_name = const_cast<char*>("com.webos.bar");
    g_assert(LSHubIsClientAllowedToQueryName(&sender_client, NULL, "com.webos.foo"));
    _LSTransportCredSetExePath(sender_cred, "/bin/bar");
    sender_client.service_name = const_cast<char*>("com.webos.bar2");
    g_assert(LSHubIsClientAllowedToQueryName(&sender_client, NULL, "com.webos.foo"));

    _LSTransportCredSetExePath(sender_cred, "/bin/client");
    sender_client.service_name = const_cast<char*>("com.webos.client");
    _LSTransportCredSetExePath(dest_cred, "/bin/server");
    dest_client.service_name = const_cast<char*>("com.webos.server");
    g_assert(LSHubIsClientAllowedToQueryName(&sender_client, &dest_client, "com.webos.server"));
    _LSTransportCredSetExePath(sender_cred, "/bin/client");
    sender_client.service_name = const_cast<char*>("com.webos.client");
    _LSTransportCredSetExePath(dest_cred, "/bin/bar");
    dest_client.service_name = const_cast<char*>("com.webos.bar");
    g_assert(!LSHubIsClientAllowedToQueryName(&sender_client, &dest_client, "com.webos.bar"));
    _LSTransportCredSetExePath(sender_cred, "/bin/foo");
    sender_client.service_name = const_cast<char*>("com.webos.foo");
    _LSTransportCredSetExePath(dest_cred, "/bin/server");
    dest_client.service_name = const_cast<char*>("com.webos.server");
    g_assert(!LSHubIsClientAllowedToQueryName(&sender_client, &dest_client, "com.webos.server"));

    _LSTransportDeinit(sender_transport);
    _LSTransportCredFree(sender_cred);
    _LSTransportDeinit(dest_transport);
    _LSTransportCredFree(dest_cred);
    _ConfigFreeSettings();
}

static void
test_LSHubPermissionIsEqual(TestData *fixture, gconstpointer user_data)
{
    LSHubPermission *a = LSHubPermissionNew(J_CSTR_TO_BUF("com.palm.a"), "/usr/bin/service");
    LSHubPermission *b = LSHubPermissionNew(J_CSTR_TO_BUF("com.palm.a"), "/usr/bin/service");

    g_assert(LSHubPermissionIsEqual(a, a));
    g_assert(LSHubPermissionIsEqual(b, b));
    g_assert(LSHubPermissionIsEqual(a, b));
    g_assert(LSHubPermissionIsEqual(b, a));

    /* Two patterns in the list of inbound */
    LSHubPermissionAddAllowedInbound(a, "com.palm.b");
    g_assert(!LSHubPermissionIsEqual(a, b) && !LSHubPermissionIsEqual(b, a));

    LSHubPermissionAddAllowedInbound(a, "com.palm.c*");
    g_assert(!LSHubPermissionIsEqual(a, b) && !LSHubPermissionIsEqual(b, a));

    LSHubPermissionAddAllowedInbound(b, "com.palm.c*");
    g_assert(!LSHubPermissionIsEqual(a, b) && !LSHubPermissionIsEqual(b, a));

    LSHubPermissionAddAllowedInbound(b, "com.palm.b");
    g_assert(LSHubPermissionIsEqual(a, b) && LSHubPermissionIsEqual(b, a));

    /* Three patterns in the list of outbound */
    LSHubPermissionAddAllowedOutbound(a, "com.palm.b");
    g_assert(!LSHubPermissionIsEqual(a, b) && !LSHubPermissionIsEqual(b, a));

    LSHubPermissionAddAllowedOutbound(a, "com.palm.c*");
    g_assert(!LSHubPermissionIsEqual(a, b) && !LSHubPermissionIsEqual(b, a));

    LSHubPermissionAddAllowedOutbound(a, "*");
    g_assert(!LSHubPermissionIsEqual(a, b) && !LSHubPermissionIsEqual(b, a));

    LSHubPermissionAddAllowedOutbound(b, "com.palm.c*");
    g_assert(!LSHubPermissionIsEqual(a, b) && !LSHubPermissionIsEqual(b, a));

    LSHubPermissionAddAllowedOutbound(b, "com.palm.b");
    g_assert(!LSHubPermissionIsEqual(a, b) && !LSHubPermissionIsEqual(b, a));

    LSHubPermissionAddAllowedOutbound(b, "*");
    g_assert(LSHubPermissionIsEqual(a, b) && LSHubPermissionIsEqual(b, a));

    g_assert(LSHubPermissionAddRequired(a, "group"));
    g_assert(LSHubPermissionAddProvided(a, "category", "group"));

    pbnjson::JObject obj;
    obj.put("service", "com.palm.a");
    obj.put("executable", "/usr/bin/service");
    obj.put("inbound", pbnjson::JArray{"com.palm.b", "com.palm.c*"});
    obj.put("outbound", pbnjson::JArray{"*", "com.palm.b", "com.palm.c*"});
    obj.put("requires", pbnjson::JArray{"group"});
    obj.put("provides", pbnjson::JObject{{"category", pbnjson::JArray{"group"}}});

    obj.put("requiredtrustLevels", pbnjson::JObject{});
    obj.put("providedtrustLevels", pbnjson::JObject{});

    pbnjson::JDomParser parser;
    parser.parse(LSHubPermissionDump(a), pbnjson::JSchema::AllSchema());

    g_assert(obj == parser.getDom());

    LSHubPermissionFree(a);
    LSHubPermissionFree(b);
}

static void
test_LSHubPermissionMerging(TestData *fixture, gconstpointer user_data)
{
    std::string service_name = "com.palm.a";
    std::string exe_name = "/usr/bin/service";
    LSHubPermission *a = LSHubPermissionNew(service_name, exe_name.c_str());
    LSHubPermission *b = LSHubPermissionNew(service_name, exe_name.c_str());
    LSHubPermission *c = LSHubPermissionNew(service_name, exe_name.c_str());

    g_assert(LSHubPermissionIsEqual(a, a));
    g_assert(LSHubPermissionIsEqual(b, b));
    g_assert(LSHubPermissionIsEqual(a, b));
    g_assert(LSHubPermissionIsEqual(b, a));

    LSHubPermissionAddAllowedInbound(a, "com.palm.1");
    LSHubPermissionAddAllowedInbound(a, "com.palm.2");
    LSHubPermissionAddAllowedInbound(b, "com.palm.3");
    LSHubPermissionAddAllowedInbound(b, "com.palm.4");
    g_assert(!LSHubPermissionIsEqual(a, b) && !LSHubPermissionIsEqual(b, a));

    LSHubPermissionAddAllowedInbound(c, "com.palm.1");
    LSHubPermissionAddAllowedInbound(c, "com.palm.2");
    LSHubPermissionAddAllowedInbound(c, "com.palm.3");
    LSHubPermissionAddAllowedInbound(c, "com.palm.4");
    g_assert(!LSHubPermissionIsEqual(a, c) && !LSHubPermissionIsEqual(b, c));
    LSHubPermissionMergePermissions(a, b);
    g_assert(LSHubPermissionIsEqual(a, c));
    g_assert(!LSHubPermissionIsEqual(a, b));
    LSHubPermissionMergePermissions(b, a);
    g_assert(LSHubPermissionIsEqual(b, c));
    g_assert(LSHubPermissionIsEqual(a, b) && LSHubPermissionIsEqual(b, a));

    LSHubPermissionAddAllowedOutbound(a, "com.palm.1");
    LSHubPermissionAddAllowedOutbound(a, "com.palm.2");
    LSHubPermissionAddAllowedOutbound(b, "com.palm.3");
    LSHubPermissionAddAllowedOutbound(b, "com.palm.4");
    g_assert(!LSHubPermissionIsEqual(a, b) && !LSHubPermissionIsEqual(b, a));

    LSHubPermissionAddAllowedOutbound(c, "com.palm.1");
    LSHubPermissionAddAllowedOutbound(c, "com.palm.2");
    LSHubPermissionAddAllowedOutbound(c, "com.palm.3");
    LSHubPermissionAddAllowedOutbound(c, "com.palm.4");
    g_assert(!LSHubPermissionIsEqual(a, c) && !LSHubPermissionIsEqual(b, c));
    LSHubPermissionMergePermissions(a, b);
    g_assert(LSHubPermissionIsEqual(a, c));
    g_assert(!LSHubPermissionIsEqual(a, b));
    LSHubPermissionMergePermissions(b, a);
    g_assert(LSHubPermissionIsEqual(b, c));
    g_assert(LSHubPermissionIsEqual(a, b) && LSHubPermissionIsEqual(b, a));

    LSHubPermissionFree(a);
    LSHubPermissionFree(b);
    LSHubPermissionFree(c);
}

static void
test_LSHubActivePermissionMap(TestData *fixture, gconstpointer user_data)
{
    std::string active_service_id = "com.palm.service";
    LSHubPermission *a = LSHubPermissionNewRef(J_CSTR_TO_BUF(active_service_id.c_str()), "/usr/bin/service");

    LSHubActivePermissionMapAddRef(a, active_service_id.c_str());
    g_assert(LSHubActivePermissionMapLookup(active_service_id.c_str()));
    g_assert(LSHubActivePermissionMapUnref(active_service_id.c_str()));
    g_assert(!LSHubActivePermissionMapLookup(active_service_id.c_str()));
    g_assert(!LSHubActivePermissionMapUnref(active_service_id.c_str()));

    LSHubPermissionUnref(a);
}

int
main(int argc, char *argv[])
{
    g_test_init(&argc, &argv, NULL);

    g_log_set_always_fatal (G_LOG_LEVEL_ERROR);
    g_log_set_fatal_mask ("LunaServiceHub", G_LOG_LEVEL_ERROR);

    g_test_add("/hub/LSHubPermissionMapLookupOldFormat", TestData, NULL, NULL, test_LSHubPermissionMapLookupOldFormat, NULL);
    g_test_add("/hub/LSHubPermissionIsEqual", TestData, NULL, NULL, test_LSHubPermissionIsEqual, NULL);
    g_test_add("/hub/LSHubPermissionMerging", TestData, NULL, NULL, test_LSHubPermissionMerging, NULL);
    g_test_add("/hub/LSHubActivePermissionMap", TestData, NULL, NULL, test_LSHubActivePermissionMap, NULL);

    return g_test_run();
}
