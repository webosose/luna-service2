// Copyright (c) 2008-2021 LG Electronics, Inc.
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

#ifndef _SECURITY_HPP_
#define _SECURITY_HPP_

#include <set>
#include <queue>
#include <string>
#include <unordered_set>
#include <unordered_map>

#include <pbnjson.hpp>
#include <luna-service2/lunaservice.h>
#include "transport_message.h"

#include "util.hpp"
#include "manifest.hpp"
#include "role_map.hpp"
#include "groups_map.hpp"
#include "service_map.hpp"
#include "permissions_map.hpp"

struct LSHubRole;
struct LSHubPermission;

/** @cond INTERNAL */

/**
 * @brief AppContainers
 *
 * Set to store list of applications containers which may
 * apply security permissions on behalf of contained apps.
 */
typedef std::set<std::string> AppContainers;

/**
 * @brief ProxyAgents
 *
 * Unordered set to store list of proxy agents which act
 * as mediators on behalf of apps/services.
 */
typedef std::unordered_set<std::string> ProxyAgents;

/**
  * @brief SecurityData
  *
  * Security settings, which get filled
  * during the config parsing.
  */

class SecurityData
{

public:
    SecurityData();

    bool AddManifest(const std::string &path, const std::string &prefix, LSError *error);
    void RemoveManifest(const std::string &path);

    bool AddExternalManifest(const std::string &path, const std::string &prefix, bool from_memory, LSError *error);
    void RemoveExternalManifest(const std::string &path, const std::string &prefix);
    void FetchManifestFiles(std::string dirpath, void* ctx);

    void LoadDevmodeCertificate(const char *path, const char *default_path);
    bool IsGroupForDevmode(const std::string &group) const;

    LSHubPermission* LookupPermission(const _LSTransportClient *client, const char *service_name) const;
    LSHubPermission* LookupPermissionProxy(const char *origin_exe, const char *origin_id,
                                           const char *origin_name, const _LSTransportClient *origin_client) const;
    void InitNonVolatileDirs(const char **dirs);
    bool IsManifestNonVolatile(const std::string &path);
    const std::unordered_set<std::string>& GetNonVolatileDirs() const { return _non_volatile_dirs; }

    static SecurityData &CurrentSecurityData();
    static int ApplyNewSecurity(void *sec_data);

    RoleMap roles;
    ServiceMap services;
    PermissionsMap permissions;
    GroupsMap groups;
    AppContainers containers;
    ProxyAgents proxy_agents;

private:
    SecurityData(SecurityData &) = delete;
    SecurityData &operator=(SecurityData &) = delete;
    SecurityData(SecurityData &&) = delete;

    std::unordered_set<std::string> _groups_for_devmode;
    std::unordered_set<std::string> _non_volatile_dirs;  //< set of directories with non-volatile manifests


#ifdef UNIT_TESTS
public:
#endif
    void LoadManifestData(ManifestData &&mdata);
    void UnloadManifestData(ManifestData &&mdata);
    SecurityData &operator=(SecurityData &&other) = default;

    // map of path to manifest
    Manifests _manifests;

    // map of id to manifests priority
    std::unordered_map<std::string, ManifestPriorityQueue> _manifests_priority;
};

bool LSHubIsClientAllowedToQueryName(_LSTransportClient *sender_client, _LSTransportClient *dest_client,
                                     const char *dest_service_name);
bool LSHubIsClientApplicationContainer(const _LSTransportClient *client);
bool LSHubIsClientProxyAgent(const _LSTransportClient *client);
bool LSHubIsClientAllowedToRequestName(const _LSTransportClient *client, const char *service_name, int32_t &client_flags);
bool LSHubIsClientAllowedToSendSignal(_LSTransportClient *client, const char *category, const char *method);
bool LSHubIsClientAllowedToSubscribeSignal(_LSTransportClient *client, const char *category, const char *method);
bool LSHubIsCallAllowed(const char *service, const char *dest_service,
                        const char *category, const char *method);
bool LSHubIsClientMonitor(const _LSTransportClient *client);
bool LSHubIsClientAllowedOutbound(_LSTransportClient *sender_client, const char *dest_service_name);
bool LSHubIsClientAllowedInbound(const _LSTransportClient *sender_client, const _LSTransportClient *dest_client,
                                  const char *dest_service_name);
bool
LSHubIsAllowedToQueryProxyName(const char *origin_exe, const char *origin_id,
                               const char *origin_name, _LSTransportClient *origin_client,
                               _LSTransportClient *dest_client, const char *dest_service_name);
bool
LSHubIsAllowedOutboundProxy(const char *origin_exe, const char *origin_id,
                            const char *origin_name, _LSTransportClient *origin_client,
                            const char *dest_service_name);
bool
LSHubIsAllowedInboundProxy(const char *origin_exe, const char *origin_id, const char *origin_name,
                            const _LSTransportClient *dest_client, const char *dest_service_name);
bool LSHubPushRole(const _LSTransportClient *client, const char *path, bool public_bus, LSError *lserror);

bool LSHubClientGetPrivileged(const _LSTransportClient *client);
bool LSHubClientGetPrivileged(const _LSTransportClient *client, bool public_bus);

bool LSHubClientGetProxy(const _LSTransportClient *client);

const char* IsMediaService(const char *service_name);

bool ProcessContainersDirectories(const char **dirs, void *ctxt, LSError *lserror);
bool ProcessProxyAgentsDirectories(const char **dirs, void *ctxt, LSError *lserror);

#ifdef UNIT_TESTS
std::string getServiceNameFromUri(pbnjson::JInput uri);
AppContainers& LSHubAppContainersGet();
bool _LSHubIsExeApplicationContainer(const std::string &exePath);
bool ParseJSONGetAPIVersions(SecurityData &security_data,
                             const pbnjson::JValue &json,
                             const std::string &json_file_path,
                             LSError *lserror);
#endif //UNIT_TESTS

/** @endcond INTERNAL */

#endif  //_SECURITY_HPP_
