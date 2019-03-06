// Copyright (c) 2008-2019 LG Electronics, Inc.
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

#include "security.hpp"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <pbnjson.hpp>
#include <luna-service2++/error.hpp>

#include <memory>
#include <sstream>
#include <unordered_map>

#include "simple_pbnjson.h"

#include "uri.h"
#include "transport.h"
#include "transport_utils.h"

#include "log.h"
#include "hub.hpp"
#include "util.hpp"
#include "conf.hpp"
#include "role.hpp"
#include "service.hpp"
#include "wildcard.hpp"
#include "pattern.hpp"
#include "role_map.hpp"
#include "client_id.hpp"
#include "permission.hpp"
#include "file_parser.hpp"
#include "patternqueue.hpp"
#include "permissions_map.hpp"
#include "active_role_map.hpp"
#include "service_permissions.hpp"
#include "active_permission_map.hpp"
#include "file_schema.hpp"
#include "hub_service.hpp"

#ifdef SECURITY_HACKS_ENABLED
#include "security_hacks.h"
#endif

/// @cond INTERNAL
/// @defgroup LunaServiceHubSecurity Security support in the hub
/// @ingroup LunaServiceHub
/// @{

#define JSON_FILE_SUFFIX    ".json"

#define ROLE_KEY            "role"
#define EXE_NAMES_KEY       "exeNames"

#define TRITON_SERVICE_EXE_PATH     "js"    /**< special "path" for triton services */

static inline bool _LSHubClientExePathMatches(const _LSTransportClient *client, const char *path);

/**
 *******************************************************************************
 * @brief Returns application containers' names data structure.
 *
 * @retval Static AppContainers data structure
 *******************************************************************************
 */
#ifndef UNIT_TESTS
static inline
#endif //UNIT_TESTS
AppContainers&
LSHubAppContainersGet()
{
    return SecurityData::CurrentSecurityData().containers;
}

/*
 * Security data, which is currently in use.
 */
SecurityData &SecurityData::CurrentSecurityData()
{
    static SecurityData data;

    return data;
}

SecurityData::SecurityData()
{
}

/**
 *******************************************************************************
 * @brief Apply pending security data as current hub
 * security settings. Comply GSourceFunc signature.
 *******************************************************************************
 */
int SecurityData::ApplyNewSecurity(void *sec_data)
{
    std::unique_ptr<SecurityData> data(static_cast<SecurityData *>(sec_data));

    CurrentSecurityData() = std::move(*data);
    for (const auto& it : external_manifests)
    {
        CurrentSecurityData().AddExternalManifest(it.first, it.second, true, nullptr);
    }

    /* Send out a signal that we've completed the scanning */
    LSHubSendConfScanCompleteSignal();

    /* false - Remove callback from the main loop */
    return false;
}

/**
 *******************************************************************************
 * @brief Returns true if the executable path is an application container.
 *
 * @param  exePath   IN  executable path
 *
 * @retval  true if executable is an application container
 * @retval  false otherwise
 *******************************************************************************
 */
#ifndef UNIT_TESTS
static inline
#endif //UNIT_TESTS
bool
_LSHubIsExeApplicationContainer(const std::string &exePath)
{
    return LSHubAppContainersGet().count(exePath);
}

bool
LSHubPushRole(const _LSTransportClient *client, const char *path, bool public_bus, LSError *lserror)
{
    /* Remove current role from active role map if there is one */
    const _LSTransportCred *cred = _LSTransportClientGetCred(client);
    if (!cred)
    {
        _LSErrorSet(lserror, MSGID_LSHUB_PUSH_ROLE_ERR, LS_TRANSPORT_PUSH_ROLE_PERMISSION_DENIED, LS_TRANSPORT_PUSH_ROLE_PERMISSION_DENIED_TEXT);
        return false;
    }

#ifndef INTEGRATION_TESTS
    /* DFISH-23679: Only root users can push a role */
    uid_t uid = _LSTransportCredGetUid(cred);
    if (uid != 0)
    {
        _LSErrorSet(lserror, MSGID_LSHUB_PUSH_ROLE_ERR, LS_TRANSPORT_PUSH_ROLE_PERMISSION_DENIED,
                    LS_TRANSPORT_PUSH_ROLE_PERMISSION_DENIED_TEXT);
        return false;
    }
#endif //INTEGRATION_TESTS

    LSHubRole *old_role = nullptr;
    pid_t pid = _LSTransportCredGetPid(cred);
    /* Unref the existing role for this pid if there is one. */
    if (LSHubRole *active = LSHubActiveRoleMapLookup(pid))
    {
        /* Check that this client is allowed to push a role */
        if (!LSHubClientGetPrivileged(client, public_bus))
        {
            _LSErrorSet(lserror, MSGID_LSHUB_PUSH_ROLE_ERR, LS_TRANSPORT_PUSH_ROLE_PERMISSION_DENIED,
                        LS_TRANSPORT_PUSH_ROLE_PERMISSION_DENIED_TEXT);
            return false;
        }

        if (LSHubRoleIsOldFormat(active))
            old_role = active;

        /* Remove old role (only for new format roles)
         * Verify that there should only be a single ref and the role is freed */
        if (!LSHubRoleIsOldFormat(active) && !LSHubActiveRoleMapUnref(pid))
        {
            _LSErrorSet(lserror, MSGID_LSHUB_PUSH_ROLE_ERR, LS_TRANSPORT_PUSH_ROLE_DUPLICATE,
                        LS_TRANSPORT_PUSH_ROLE_DUPLICATE_TEXT);
            return false;
        }
    }
    else
    {
        /* Couldn't verify that this pid is allowed to push a role */
        _LSErrorSet(lserror, MSGID_LSHUB_PUSH_ROLE_ERR, LS_TRANSPORT_PUSH_ROLE_PERMISSION_DENIED,
                    LS_TRANSPORT_PUSH_ROLE_PERMISSION_DENIED_TEXT);
        return false;
    }

    PermissionArray perms;
    RolePtr role(nullptr, LSHubRoleUnref);
    BusTypeRoleFlag bus_flag = (public_bus) ? PUBLIC_BUS_ROLE : PRIVATE_BUS_ROLE;
    if (old_role)
    {
        ParseOldRoleFile(path, std::string(),  uint32_t(bus_flag), role, perms, lserror);
    }
    else
    {
        ServiceToTrustMap required;
		std::string trustLevel;
        ParseRoleFile(path, std::string(), role,perms, required, trustLevel, lserror);
    }

    if (!role)
    {
        LOG_LSERROR(MSGID_LSHUB_ROLE_FILE_ERR, lserror);
        LSErrorFree(lserror);
        _LSErrorSet(lserror, MSGID_LSHUB_PUSH_ROLE_ERR, LS_TRANSPORT_PUSH_ROLE_FILE_ERROR, LS_TRANSPORT_PUSH_ROLE_FILE_ERROR_TEXT, path);
        return false;
    }

    if (old_role)
    {
        // Drop allowed services for current bus
        LSHubRoleDropBusFlag(old_role, bus_flag);
        // Merge allowed names from pushed role
        LSHubRoleMergeAllowedNames(old_role, role.get());
        // Merge service bus flags from pushed role
        LSHubRoleMergeFlags(old_role, role.get());
        // Role priviledge for current bus
        LSHubRoleType priv_to_remove = (public_bus) ? LSHubRoleTypePrivilegedPublic : LSHubRoleTypePrivileged;
        // Drop priviledge for current bus
        old_role->type ^= priv_to_remove;
    }
    else
    {
        /* ignore any permissions in the file */
        if (!LSHubActiveRoleMapAddRef(pid, role.get(), lserror))
        {
            LOG_LSERROR(MSGID_LSHUB_ROLE_FILE_ERR, lserror);
            LSErrorFree(lserror);
            _LSErrorSet(lserror, MSGID_LSHUB_PUSH_ROLE_ERR, LS_TRANSPORT_PUSH_ROLE_UNKNOWN_ERROR, LS_TRANSPORT_PUSH_ROLE_UNKNOWN_ERROR_TEXT);
            return false;
        }
    }
    return true;
}

/// @brief Determine if a client is privileged
///
/// A client is privileged if security is disabled, or it's declared privileged in role files.
/// Look up active role map by client PID, and check its role.
///
/// @param[in]  client    Client to check
/// @param[in]  bus_flag  Type of connection to the bus (legacy vs new, public vs private)
/// @return true if the service is privileged
static bool
LSHubClientGetPrivilegedFlag(const _LSTransportClient *client, BusTypeRoleFlag bus_flag)
{
    // if security is not enabled or the transport doesn't
    // support security then just say that the client is privileged
    bool privileged = !g_conf_security_enabled;

    /* look up the role in role maps */
    if (!privileged)
    {
        const LSHubRole *role{nullptr};
        if (const char *app_id = _LSTransportClientGetApplicationId(client))
        {
            role = SecurityData::CurrentSecurityData().roles.Lookup(app_id);
        }
        else
        {
            auto *cred = _LSTransportClientGetCred(client);
            role =  cred ? LSHubActiveRoleMapLookup(_LSTransportCredGetPid(cred))
                         : nullptr;
        }
        privileged = role && LSHubRoleIsPrivileged(role, bus_flag);
    }

    return privileged;
}

/// @brief Determine if a legacy client is privileged
/// @param[in] client
/// @param[in] public_bus
/// @return true if the service is privileged
bool
LSHubClientGetPrivileged(const _LSTransportClient *client, bool public_bus)
{
    return LSHubClientGetPrivilegedFlag(client, public_bus ? PUBLIC_BUS_ROLE : PRIVATE_BUS_ROLE);
}

/// @brief Determine if a client is privileged
/// @param[in] client
/// @return true if the service is privileged
bool
LSHubClientGetPrivileged(const _LSTransportClient *client)
{
    return LSHubClientGetPrivilegedFlag(client, NO_BUS_ROLE);
}

static bool
_LSHubSecurityPatternQueueAllowServiceName(_LSHubPatternQueue *q, const char *service_name)
{
    LS_ASSERT(q != NULL);

    /* un-named services are represented as empty strings in the map */
    if (service_name == NULL)
    {
        service_name = "";
    }
    else if (service_name[0] == '\0')
    {
        /* empty strings are not allowed as service names */
        return false;
    }

    if (_LSHubPatternQueueHasMatch(q, service_name))
    {
        return true;
    }

    LOG_LS_WARNING(MSGID_LSHUB_NO_PERMISSION_FOR_NAME, 0,
                   "Can not find match for '%s' in pattern queue '%s'",
                   service_name, _LSHubPatternQueueDump(q).c_str());

    return false;
}

/* true if the client's executable is application container */
bool
LSHubIsClientApplicationContainer(const _LSTransportClient *client)
{
    LS_ASSERT(client);

    /* Use executable path to verify if connected peer is application container */
    const _LSTransportCred *cred = _LSTransportClientGetCred(client);
    if (!cred || !_LSTransportCredGetExePath(cred))
        return false;

    return _LSHubIsExeApplicationContainer(_LSTransportCredGetExePath(cred));
}

/* true if the client is allowed to register the requested service name */
bool
LSHubIsClientAllowedToRequestName(const _LSTransportClient *client, const char *service_name, int32_t &client_flags)
{
    LS_ASSERT(client != NULL);

#ifdef SECURITY_HACKS_ENABLED
    if (_LSIsTrustedService(service_name))
    {
        LOG_LS_INFO(MSGID_LS_NOT_AN_ERROR, 0, "Security hacks was applyed for: %s", service_name);
        return true;
    }
#endif

    const _LSTransportCred *cred = _LSTransportClientGetCred(client);

    if (!cred)
    {
        return false;
    }

    const LSHubRole *role{nullptr};

    // for non-native application services use application Id instead of executable path
    const char* app_id = _LSTransportClientGetApplicationId(client);
    if (app_id)
    {
        role =  SecurityData::CurrentSecurityData().roles.Lookup(app_id);
        if (!role)
        {
            LOG_LS_WARNING(MSGID_LSHUB_NO_ROLE_FILE, 1,
                         PMLOGKS("APP_ID", app_id), "No role file for application id: \"%s\"", app_id);
            return !g_conf_security_enabled;
        }
    }
    else
    {
        /* Use exe_path in client credentials to look up role file and allowed service names */
        /* first check the active role map to see if this process already has a role
         * associated with it */
        pid_t pid = _LSTransportCredGetPid(cred);
        LSHubRole *active_role = LSHubActiveRoleMapLookup(pid);

        if (active_role)
        {
            /* increment role ref count -- this function is called once per LSRegister()
             * and we will clean up on LSUnregister() or disconnect */
            LSHubRoleRef(active_role);
            role = active_role;
        }
        else
        {
            /* Check the role map from disk based on exe path */

            const char *exe_path = _LSTransportCredGetExePath(cred);
            if (!exe_path)
            {
                return false;
            }

            role =  SecurityData::CurrentSecurityData().roles.Lookup(exe_path);
            if (!role)
            {
                /* service name is not in role file set, so deny request */
                LOG_LS_ERROR(MSGID_LSHUB_NO_ROLE_FILE, 1,
                             PMLOGKS("EXE", exe_path),
                             "No role file for executable: \"%s\" (cmdline: %s)",
                             exe_path, _LSTransportCredGetCmdLine(cred));
                return !g_conf_security_enabled;
            }

            /* create copy, ref, and add to active role map */
            LS::Error lserror;
            auto copy = mk_ptr(LSHubRoleCopyRef(role), LSHubRoleUnref);
            if (!LSHubActiveRoleMapAddRef(pid, copy.get(), lserror.get()))  /* ref count = 2 */
            {
                LOG_LSERROR(MSGID_LSHUB_DATA_ERROR, lserror.get());
            }
        }
    }

    /* check to see if role allows this name */
    if (LSHubRoleIsNameAllowed(role, service_name))
    {
        if (LSHubRoleIsOldFormat(role))
            client_flags |= _LSTransportFlagOldConfig;
        bool is_private_allowed = LSHubRoleIsPrivateAllowed(role, service_name);
        if (is_private_allowed || !g_conf_security_enabled)
            client_flags |= _LSTransportFlagPrivateBus;
        bool is_public_allowed = LSHubRoleIsPublicAllowed(role, service_name);
        if (is_public_allowed || !g_conf_security_enabled)
            client_flags |= _LSTransportFlagPublicBus;
        return true;
    }
    if (LSHubRoleIsPrivileged(role, NO_BUS_ROLE))
    {
        LOG_LS_INFO(MSGID_LS_NOT_AN_ERROR, 0, "LSHubRoleIsPrivileged hacks was applyed for: %s", service_name);
        return true;
    }
    LOG_LS_ERROR(MSGID_LSHUB_NO_PERMISSION_FOR_NAME, 3,
                 PMLOGKS("APP_ID", service_name),
                 PMLOGKS("ROLE_ID", role ? role->id.c_str() : "null"),
                 PMLOGKS("EXE", _LSTransportCredGetExePath(cred)),
                 "Executable: \"%s\" (cmdline: %s) "
                 "does not have permission to register name: \"%s\"",
                 _LSTransportCredGetExePath(cred),
                 _LSTransportCredGetCmdLine(cred),
                 service_name);

    if (!g_conf_security_enabled)
    {
        if (LSHubRoleIsOldFormat(role))
            client_flags |= _LSTransportFlagOldConfig;
        client_flags |= _LSTransportFlagPrivateBus;
        client_flags |= _LSTransportFlagPublicBus;
        return true;
    }

    return false;
}

/**
 *******************************************************************************
 * @brief Returns true if the specified client is the monitor binary. If the
 * transport does not support security features this will always return true.
 *
 * @param  client   IN  client to check
 *
 * @retval  true if specified client is monitor binary
 * @retval  false otherwise
 *******************************************************************************
 */
bool
LSHubIsClientMonitor(const _LSTransportClient *client)
{
    LS_ASSERT(client != NULL);

    return _LSHubClientExePathMatches(client, g_conf_monitor_exe_path);
}

/**
 *******************************************************************************
 * @brief Returns true if the client's exe path matches the given path.
 *
 * @param  client   IN  client
 * @param  path     IN  path to compare
 *
 * @retval true if client's exe path matches given path
 * @retval false otherwise
 *******************************************************************************
 */
static inline bool
_LSHubClientExePathMatches(const _LSTransportClient *client, const char *path)
{
    if (!path)
        return false;

    const _LSTransportCred *cred = _LSTransportClientGetCred(client);

    if (!cred)
    {
        return false;
    }

    const char *exe_path = _LSTransportCredGetExePath(cred);

    if (!exe_path)
    {
        return false;
    }

    if (strcmp(_LSTransportCredGetExePath(cred), path) == 0)
    {
        return true;
    }

    return false;
}

static inline void
_LSHubPrintPermissionsMessage(const _LSTransportClient *client, const char *sender_service_name,
                              const char *dest_service_name, bool inbound, bool is_error)
{
    G_GNUC_UNUSED const _LSTransportCred *cred  = _LSTransportClientGetCred(client);

    if (inbound)
    {
        LOG_LS_ERROR(MSGID_LSHUB_NO_INBOUND_PERMS, 4,
                     PMLOGKS("DEST_APP_ID", dest_service_name),
                     PMLOGKS("SRC_APP_ID", sender_service_name),
                     PMLOGKS("EXE", _LSTransportCredGetExePath(cred)),
                     PMLOGKFV("PID", LS_PID_PRINTF_FORMAT, LS_PID_PRINTF_CAST(_LSTransportCredGetPid(cred))),
                     "Permissions does not allow inbound connections from \"%s\" to \"%s\" (cmdline: %s)",
                     sender_service_name, dest_service_name, _LSTransportCredGetCmdLine(cred));
    }
    else
    {
        /* outbound */
        LOG_LS_ERROR(MSGID_LSHUB_NO_OUTBOUND_PERMS, 4,
                     PMLOGKS("DEST_APP_ID", dest_service_name),
                     PMLOGKS("SRC_APP_ID", sender_service_name),
                     PMLOGKS("EXE", _LSTransportCredGetExePath(cred)),
                     PMLOGKFV("PID", LS_PID_PRINTF_FORMAT, LS_PID_PRINTF_CAST(_LSTransportCredGetPid(cred))),
                     "\"%s\" does not have sufficient outbound permissions to communicate with \"%s\" (cmdline: %s)",
                     sender_service_name, dest_service_name, _LSTransportCredGetCmdLine(cred));
    }
}

static inline void
_LSHubPrintSignalPermissionsMessage(const _LSTransportClient *client, bool is_send,
                                    const char *category, const char *method)
{
    G_GNUC_UNUSED const char *service_name = _LSTransportClientGetServiceName(client);
    G_GNUC_UNUSED const _LSTransportCred *cred = _LSTransportClientGetCred(client);

    LOG_LS_ERROR(MSGID_LSHUB_NO_SIGNAL_PERMS, 3,
                 PMLOGKS("APP_ID", service_name),
                 PMLOGKS("EXE", _LSTransportCredGetExePath(cred)),
                 PMLOGKFV("PID", LS_PID_PRINTF_FORMAT, LS_PID_PRINTF_CAST(_LSTransportCredGetPid(cred))),
                 "\"%s\" is not allowed to %s signal %s/%s (cmdline: %s)", service_name,
                 is_send ? "send" : "subscribe",
                 category, method,
                 _LSTransportCredGetCmdLine(cred));
}

bool
LSHubIsClientAllowedOutbound(_LSTransportClient *sender_client,
                              const char *dest_service_name)
{
    LS_ASSERT(sender_client != NULL);
    LS_ASSERT(dest_service_name != NULL);

    const char *sender_service_name = _LSTransportClientGetServiceName(sender_client);

    if ((sender_service_name == NULL) && g_conf_allow_null_outbound_by_default)
    {
        return true;
    }

    auto perm = SecurityData::CurrentSecurityData().LookupPermission(sender_client, sender_service_name);
    if (perm && perm->outbound && _LSHubSecurityPatternQueueAllowServiceName(perm->outbound, dest_service_name))
    {
        return true;
    }

    return !g_conf_security_enabled;
}

bool
LSHubIsClientAllowedInbound(const _LSTransportClient *sender_client, const _LSTransportClient *dest_client,
                             const char *dest_service_name)
{
    LS_ASSERT(sender_client != NULL);
    LS_ASSERT(dest_service_name != NULL);

    const char *sender_service_name = _LSTransportClientGetServiceName(sender_client);

    /* Always allow the monitor to send messages to everyone without explicitly adding
     * it to each role file */
    if (LSHubIsClientMonitor(sender_client))
    {
        return true;
    }

    /* If target service is up, we check active permissions. But if service
     * is down and permission have multiple entries for different exepaths,
     * we have no idea what exename this service will have, so just
     * leave client to wait until the service will connect */
    LSHubPermission *perm = LSHubActivePermissionMapLookup(dest_client);
    if (!perm)
    {
        auto perms = SecurityData::CurrentSecurityData().permissions.LookupServicePermissions(dest_service_name);
        /* If we have no entries with given service name, return false */
        if (!perms)
        {
            _LSHubPrintPermissionsMessage(sender_client, sender_service_name, dest_service_name,
                                          true, g_conf_security_enabled);
            return !g_conf_security_enabled;
        }
        /* Else if we have single entry for the service name, we could check this entry */
        else if (g_slist_length(perms->permissions) == 1)
        {
            perm = perms->default_permission;
        }
    }

    // Check inbound permissions if found target permission
    // If inbound permissions are empty - allow all inbound connections by default
    if (perm && perm->inbound)

    {
        if (!_LSHubPatternQueueIsEmpty(perm->inbound)
            && !_LSHubSecurityPatternQueueAllowServiceName(perm->inbound, sender_service_name))
        {
            _LSHubPrintPermissionsMessage(sender_client, sender_service_name, dest_service_name,
                                          true, g_conf_security_enabled);
            return !g_conf_security_enabled;
        }
    }

    return true;
}

bool
LSHubIsClientAllowedToQueryName(_LSTransportClient *sender_client, _LSTransportClient *dest_client,
                                const char *dest_service_name)
{
    LS_ASSERT(sender_client != NULL);
    LS_ASSERT(dest_service_name != NULL);

    const char* service_name = _LSTransportClientGetServiceName(sender_client);
#ifdef SECURITY_HACKS_ENABLED
    if (_LSIsTrustedService(service_name) || _LSIsTrustedService(dest_service_name))
    {
        return true;
    }
#endif

    if (!LSHubIsClientAllowedOutbound(sender_client, dest_service_name))
    {
        _LSHubPrintPermissionsMessage(sender_client, service_name, dest_service_name,
                                  false, g_conf_security_enabled);
        return false;
    }

    if (!LSHubIsClientAllowedInbound(sender_client, dest_client, dest_service_name))
    {
        _LSHubPrintPermissionsMessage(sender_client, service_name, dest_service_name,
                                      true, g_conf_security_enabled);
        return false;
    }

    return true;
}

bool
LSHubIsClientAllowedToSendSignal(_LSTransportClient *client, const char *category, const char *method)
{
    LS_ASSERT(client != NULL);

    if (!g_conf_security_enabled)
    {
        return true;
    }

    const char *service_name = _LSTransportClientGetServiceName(client);
    if (!service_name)
    {
        LOG_LS_ERROR(MSGID_LSHUB_NO_SIGNAL_PERMS, 1,
                     PMLOGKS("EXE", _LSTransportCredGetExePath(_LSTransportClientGetCred(client))),
                     "Anonymous signal publish %s/%s prohibited",
                     category, method);
        return false;
    }

    std::string object_path{"/signal/publish"};
    object_path += category;

    if (LSHubIsCallAllowed(service_name, "com.webos.service.bus", object_path.c_str(), method))
        return true;

    _LSHubPrintSignalPermissionsMessage(client, true, category, method);
    return false;
}

bool LSHubIsClientAllowedToSubscribeSignal(_LSTransportClient *client, const char *category, const char *method)
{
    LS_ASSERT(client != NULL);

    if (!g_conf_security_enabled)
    {
        return true;
    }

    // Allow everybody to subscribe for service status.
    if (!strcmp(SERVICE_STATUS_CATEGORY, category))
        return true;

    const char *service_name = _LSTransportClientGetServiceName(client);

#ifdef SECURITY_COMPATIBILITY
    if (!service_name)
    {
        LOG_LS_WARNING(MSGID_LSHUB_NO_SIGNAL_PERMS, 1,
                       PMLOGKS("EXE", _LSTransportCredGetExePath(_LSTransportClientGetCred(client))),
                       "Anonymous signal subscription %s/%s allowed for compatibility",
                       category, method);
        return true;
    }
#endif

    std::string object_path{"/signal/subscribe"};
    object_path += category;

    if (LSHubIsCallAllowed(service_name, "com.webos.service.bus", object_path.c_str(), method))
        return true;

    _LSHubPrintSignalPermissionsMessage(client, false, category, method);
    return false;
}

bool
LSHubIsCallAllowed(const char *service, const char *dest_service,
                   const char *category, const char *method)
{
    LS_ASSERT(service);
    LS_ASSERT(category);

    if (strcmp(service, dest_service) == 0)
    {
        return true;
    }

    Groups req;
    const GroupsMap &gropus = SecurityData::CurrentSecurityData().groups;
    CategoryMap prov_map = gropus.GetProvided(dest_service);

#ifdef SECURITY_COMPATIBILITY
    _ClientId* id = AvailableMapLookup(service);
    if (!id)
    {
        id = AvailableMapLookupByUniqueName(service);
        if (id)
            LOG_LS_WARNING(MSGID_LSHUB_ANONYMOUS_CLIENT, 0,
                           "Deprecated: checking if anonymous client (%s) can call luna://%s/%s/%s",
                           service, dest_service, category, method);
    }
    LSHubPermission *permission = id ? LSHubActivePermissionMapLookup(id->client) : nullptr;
    if (permission)
    {
        req = LSHubPermissionGetRequired(permission);
    }
    else
    {
#endif
        req = gropus.GetRequired(service);
#ifdef SECURITY_COMPATIBILITY
    }

    if (prov_map.empty() || req.empty()) // For old services
    {
        return true;
    }
#endif //SECURITY_COMPATIBILITY

    std::string req_method(category);
    //root path always ends with '/'
    if (method)
    {
        if (req_method.back() != '/')
            req_method.push_back('/');
        req_method += method;
    }

    // For each provided groups find groups for which requested method match to groups' method's pattern
    for (const auto &it : prov_map)
    {
        const std::string &pattern = it.first;
        PatternMatchResult ret = globPatternMatch(pattern.c_str(), req_method.c_str());
        if (ret == PatternMatchResult::PATTERN_SAME || ret == PatternMatchResult::PATTERN_MATCH)
        {
            // For matched provided groups find first intersection with required groups
            const Groups &prov = it.second;
            for (auto it_req = req.begin(); it_req != req.end(); ++it_req)
            {
                for (auto it_prov = prov.begin(); it_prov != prov.end(); ++it_prov)
                {
                    // If provided group equal to required group it means that method is allowed
                    if (*it_prov == *it_req)
                        return true;
                }
            }
        }
    }

    // Requested method mismatches to patterns or is no groups intersection
    return false;
}

#ifndef UNIT_TESTS
static
#endif
std::string getServiceNameFromUri(pbnjson::JInput uri)
{
    auto *end = static_cast<const char *>(memchr(uri.m_str, '/', uri.m_len));
    size_t len = end ? (end - uri.m_str) : uri.m_len;
    return {uri.m_str, len};
}

/// @brief Parse file with container definition
///
/// @param[in] security_data Security data container to work with
/// @param[in] filepath
/// @param[in,out] lserror
/// @return true on success
bool
ProcessContainersFile(SecurityData &security_data, const std::string &filepath, LSError *lserror)
{
    LOG_LS_DEBUG("%s: parsing JSON from file: \"%s\"", __func__, filepath.c_str());

    auto json = pbnjson::JDomParser::fromFile(filepath.c_str(), container_schema);
    if (!json)
    {
        _LSErrorSet(lserror, MSGID_LSHUB_CONTAINERS_FILE_ERR, -1,
                    "%s: Failed to parse containers file %s: %s",
                    __func__, filepath.c_str(), json.errorString().c_str());
        return false;
    }

    pbnjson::JValue apps_array{json[EXE_NAMES_KEY]};
    for (ssize_t idx = 0; idx < apps_array.arraySize(); ++idx)
    {
        security_data.containers.insert(apps_array[idx].asString());
    }

    return true;
}

/// @brief Parse directory with container definition files
///
/// @param[in] security_data Security data container to work with
/// @param[in] dirpath
/// @param[in,out] lserror
/// @return true on success
bool
ProcessContainersDirectory(SecurityData &security_data, const char *dirpath, LSError *lserror)
{
    /* process all the container files in the specified directory */
    LS_ASSERT(dirpath != NULL);
    LOG_LS_DEBUG("%s: parsing containers directory: \"%s\"\n", __func__, dirpath);

    GErrorPtr gerror;
    auto dir = mk_ptr(g_dir_open(dirpath, 0, gerror.pptr()), g_dir_close);
    if (!dir)
    {
        if (gerror->code == G_FILE_ERROR_NOENT)
        {
            LOG_LS_DEBUG("Skipping missing containers directory %s", dirpath);
            return true;
        }

        _LSErrorSetFromGError(lserror, MSGID_LSHUB_NO_CONTAINERS_DIR, gerror.release());
        return false;
    }

    const char *filename = NULL;
    while ((filename = g_dir_read_name(dir.get())) != NULL)
    {
        /* check file extension */
        if (g_str_has_suffix(filename, JSON_FILE_SUFFIX))
        {
            std::string full_path(dirpath);
            full_path += "/";
            full_path += filename;

            if (!ProcessContainersFile(security_data, full_path, lserror))
            {
                LOG_LSERROR(MSGID_LSHUB_CONTAINERS_FILE_ERR, lserror);
                LSErrorFree(lserror);
            }
        }
    }

    return true;
}

/// @brief Parse directories with container definition files
///
/// @param[in] dirs
/// @param[in] ctxt
/// @param[in,out] lserror
/// @return true on success
bool
ProcessContainersDirectories(const char **dirs, void *ctxt, LSError *lserror)
{
    /* process all the container files in the specified directories */
    LS_ASSERT(dirs != NULL);
    LS_ASSERT(ctxt != nullptr);

    auto security_data = static_cast<SecurityData *>(ctxt);

    for (const char **cur_dir = dirs; cur_dir != NULL && *cur_dir != NULL; cur_dir++)
    {
        if (!ProcessContainersDirectory(*security_data, *cur_dir, lserror))
        {
            LOG_LSERROR(MSGID_LSHUB_CONTAINERS_FILE_ERR, lserror);
            LSErrorFree(lserror);
        }
    }

    return true;
}

/// @brief Look up permissions for a given client.
///
/// @param[in] client        Client for which to query in the active role map
/// @param[in] service_name  Service name to fall back to the role configuration.
/// @return found permissions or nullptr
LSHubPermission*
SecurityData::LookupPermission(const _LSTransportClient *client, const char *service_name) const
{
    const char *lookup_service = service_name ? service_name : "";
    const char *permission_key = nullptr;

    // If client is available first look up effective permissions
    if (client)
    {
        LSHubPermission *perm = LSHubActivePermissionMapLookup(client);
        if (perm)
            return perm;

        permission_key = _LSTransportClientGetApplicationId(client);
        if (!permission_key && _LSTransportClientGetCred(client))
            permission_key = _LSTransportCredGetExePath(_LSTransportClientGetCred(client));
    }

    return permissions.Lookup(lookup_service, permission_key);
}

bool SecurityData::AddManifest(const std::string &path, const std::string &prefix, LSError *error)
{
    LOG_LS_DEBUG("%s: parsing manifest from file: \"%s\"", __func__, path.c_str());

    auto json = pbnjson::JDomParser::fromFile(path.c_str(), manifest_schema);
    if (!json)
    {
         _LSErrorSet(error, MSGID_LSHUB_MANIFEST_FILE_ERROR, -1,
                     "Failed to parse manifest file \"%s\" with error: \"%s\"",
                     path.c_str(), json.errorString().c_str());
        return false;
    }

    Manifest manifest(path, prefix);
    if (!manifest.parse(error))
        return false;

    if (_manifests.find(manifest) != _manifests.end())
    {
        LOG_LS_INFO(MSGID_LSHUB_MANIFEST_FILE_ERROR, 0, "Skipping already loaded manifest <%s>", path.c_str());
        return false;
    }

    ManifestData data;
    if (!ManifestData::ProcessManifest(json, prefix, data, error))
        return false;

    const Manifest *ref = &(*_manifests.insert(std::move(manifest)).first);

    auto &priority = _manifests_priority[ref->id];
    const Manifest *active = priority.top();
    priority.push(ref);

    if (ref != priority.top())
    {
        return true;
    }

    if (active)
    {
        ManifestData old;
        ManifestData::ProcessManifest(active->path, active->prefix, old, nullptr);
        UnloadManifestData(std::move(old));
    }

    LoadManifestData(std::move(data));
    return true;
}

void SecurityData::RemoveManifest(const std::string &path)
{
    auto found = _manifests.find(Manifest(path));
    if (found == _manifests.end())
        return;

    const std::string& id = found->id;
    ManifestPriorityQueue &queue = _manifests_priority[id];

    const Manifest *active = queue.top();
    const Manifest *ref = &(*found);

    queue.remove(ref);
    if (active == ref)
    {
        active = queue.top();
        if (!active)
        {
            ManifestData old_manifest;
            ManifestData::ProcessManifest(ref->path, ref->prefix, old_manifest, nullptr);
            UnloadManifestData(std::move(old_manifest));
        }
        else if (active->version.compare(ref->version) != SemanticVersion::Precedence::Equal)
        {
            ManifestData old_manifest;
            ManifestData::ProcessManifest(ref->path, ref->prefix, old_manifest, nullptr);
            UnloadManifestData(std::move(old_manifest));

            ManifestData new_manifest;
            ManifestData::ProcessManifest(active->path, active->prefix, new_manifest, nullptr);
            LoadManifestData(std::move(new_manifest));
        }
    }

    if (queue.empty())
        _manifests_priority.erase(id);
    _manifests.erase(found);
}

bool SecurityData::AddExternalManifest(const std::string &path, const std::string &prefix, bool from_memory, LSError *error)
{
    LOG_LS_DEBUG("%s: parsing manifest from file: \"%s\"", __func__, path.c_str());

    Manifest manifest(path, prefix);
    if (!manifest.parse(error))
        return false;

    if (_manifests.find(manifest) != _manifests.end())
    {
        _LSErrorSet(error, MSGID_LSHUB_MANIFEST_FILE_ERROR, -1, "Skipping already loaded manifest <%s>", path.c_str());
        return false;
    }

    ExternalManifestData data(path, prefix);
    if (from_memory)
    {
        data.LoadFromMemory();
    }
    else
    {
        if (!data.LoadFromStorage(error))
            return false;
    }

    const Manifest *ref = &(*_manifests.insert(std::move(manifest)).first);

    auto &priority = _manifests_priority[ref->id];
    const Manifest *active = priority.top();
    priority.push(ref);

    if (ref != priority.top())
    {
        return true;
    }

    if (active)
    {
        ExternalManifestData old_manifest(active->path, active->prefix);

        if (IsManifestNonVolatile(active->path))
            old_manifest.LoadFromStorage(error);
        else
            old_manifest.LoadFromMemory();

        UnloadManifestData(std::move(old_manifest));
    }

    if (!from_memory) data.Save();
    LoadManifestData(std::move(data));
    return true;
}

void SecurityData::FetchManifestFiles(std::string dirpath, void* ctx)
{
    for (auto it = _manifests.begin(); it != _manifests.end(); ++it)
    {
        const auto &manifest = *it;
        FileIterator *iterator = static_cast<FileIterator*>(ctx);
        if (manifest.path.compare(0, dirpath.size(), dirpath) == 0)
            (*iterator)(manifest.path);
    }
}

void SecurityData::RemoveExternalManifest(const std::string &path, const std::string &prefix)
{
    auto found = _manifests.find(Manifest(path));
    if (found == _manifests.end())
        return;

    const std::string &id = found->id;
    ManifestPriorityQueue &queue = _manifests_priority[id];

    const Manifest *active = queue.top();
    const Manifest *ref = &(*found);

    queue.remove(ref);
    if (active == ref)
    {
        active = queue.top();
        if (!active)
        {
            ExternalManifestData old_manifest(path, prefix);
            old_manifest.LoadFromMemory();
            old_manifest.Remove();
            UnloadManifestData(std::move(old_manifest));
        }
        else if (active->version.compare(ref->version) != SemanticVersion::Precedence::Equal)
        {
            ExternalManifestData old_manifest(path, prefix);
            old_manifest.LoadFromMemory();
            old_manifest.Remove();
            UnloadManifestData(std::move(old_manifest));

            ExternalManifestData new_manifest(active->path, active->prefix);
            LS::Error error;
            if (IsManifestNonVolatile(active->path))
               new_manifest.LoadFromStorage(error);
            else
               new_manifest.LoadFromMemory();
            LoadManifestData(std::move(new_manifest));
        }
    }

    if (queue.empty())
        _manifests_priority.erase(id);
    _manifests.erase(found);
}

void SecurityData::LoadManifestData(ManifestData &&data)
{
    // Apply our data to current security tree
    for (auto &role : data.roles)
    {
        roles.Add(std::move(role));
    }

    for (auto &perm : data.perms)
    {
        permissions.Add(std::move(perm));
    }

    for (auto &service : data.services)
    {
        services.Add(std::move(service));
    }

    for (const auto &item : data.requires)
    {
        const std::string &name = item.first;
        for (const auto &group : item.second)
        {
            groups.AddRequired(name.c_str(), group);
        }
    }

    for (const auto &item : data.provides)
    {
        const std::string &name = item.first;
        for (const auto &pattern : item.second) 
        {
            groups.AddProvided(getServiceNameFromUri(pattern).c_str(), pattern, name.c_str());
        }
    }

    //TBD: Do we have to add provided as well as required trustlevels ??
    //Search group in provided and get service name
    if (!data.trust_level_provided.empty()) { // This condition will not be needed once everyone has trust level
      //DumpTrustMapToFile("security_cpp_LoadManifest_trust_level_provided", data.trust_level_provided, "Security_cpp_LoadManifest_trust_level_provided");
      for (const auto &item : data.trust_level_provided)
      {
          const std::string service_name_provided = item.first;
          LOG_LS_DEBUG("Found trustmap..service_name : %s", service_name_provided.c_str());
          TrustMap trusts_map;
          for (const auto &map : item.second)
          {
              for(const auto &e : map.second) {
                  std::string g = map.first;
                  trusts_map[g].push_back(e);
              }
          }
          groups.AddProvidedTrustLevel(service_name_provided.c_str(), trusts_map);
      }
    }

    if (!data.trust_level_required.empty()) { // This condition will not be needed once everyone has trust level
      //DumpTrustMapToFile("security_cpp_LoadManifest_trust_level_required", data.trust_level_required, "Security_cpp_LoadManifest_trust_level_required");
      std::string service_name_required;
      for (const auto &item : data.trust_level_required)
      {
          service_name_required = item.first;
          LOG_LS_DEBUG("Found trustmap..groupname : %s", service_name_required.c_str());
          TrustMap trusts_map;
          for (const auto &map : item.second)
          {
              for(const auto &e : map.second) {
                  std::string g = map.first;
                  trusts_map[g].push_back(e);
              }
          }
          groups.AddRequiredTrustLevel(service_name_required.c_str(), trusts_map);

      }
	  groups.AddRequiredTrustLevelAsString(service_name_required.c_str(), data.trustLevel);
    }
    //TBD: Check here if we need to add trust inormation
}

void SecurityData::UnloadManifestData(ManifestData &&data)
{
    for (const auto &role : data.roles)
    {
        roles.Remove(role->id);
    }

    for (const auto &perm : data.perms)
    {
        permissions.Remove(perm->service_name, perm->exe_path);
    }

    for (const auto &service : data.services)
    {
        services.Remove((const char**)service->service_names, service->num_services);
    }

    for (const auto &item : data.requires)
    {
        const std::string& name = item.first;
        for (const auto &group : item.second)
            groups.RemoveRequired(name.c_str(), group);
    }

    for (const auto &item : data.provides)
    {
        const std::string &name = item.first;
        for (const auto &pattern : item.second)
        {
            groups.RemoveProvided(getServiceNameFromUri(pattern).c_str(), pattern, name.c_str());
        }
    }

    // Remove provided trust levels
    for (const auto &item : data.trust_level_provided)
    {
        const std::string service_name = item.first;
        for (const auto &map : item.second)
        {
            const std::string group = map.first;
            for (const auto &trust : map.second)
                groups.RemoveProvidedTrustLevel((service_name).c_str(), group.c_str(), trust);
        }
    }

    // Remove required trust levels
    for (const auto &item : data.trust_level_required)
    {
        const std::string service_name = item.first;
        for (const auto &map : item.second)
        {
            const std::string group = map.first;
            for (const auto &trust : map.second)
                groups.RemoveRequiredTrustLevel((service_name).c_str(), group.c_str(), trust);
        }
    }
}

void SecurityData::LoadDevmodeCertificate(const char *path, const char *default_path)
{
    LS_ASSERT(path && default_path);

    if (!g_file_test(path, G_FILE_TEST_EXISTS))
    {
        if (!g_file_test(default_path, G_FILE_TEST_EXISTS))
        {
            LOG_LS_INFO(MSGID_LSHUB_DEVMODE, 0, "Devmode certificate is not installed. Devmode will not be used");
            return;
        }
        path = default_path;
    }

    auto v = pbnjson::JDomParser::fromFile(path);
    if (!v.isObject())
    {
        LOG_LS_ERROR(MSGID_LSHUB_DEVMODE_ERR, 0,
                     "Invalid devmode certificate file: %s", path);
        return;
    }

    // Binaries and applications marked "devmode" will be restricted to only those groups
    // that are listed in the devmode certificate under "devmodeGroups".
    auto devmode_groups = v["devmodeGroups"];
    if (!devmode_groups.isArray())
    {
        LOG_LS_ERROR(MSGID_LSHUB_DEVMODE_ERR, 0, "The field `devmodeGroups' should be array");
        return;
    }

    for (const auto &group : devmode_groups.items())
    {
        if (!group.isString())
            LOG_LS_WARNING(MSGID_LSHUB_DEVMODE_ERR, 0, "Skipping non-string among `devmodeGroups'");
        else
            _groups_for_devmode.insert(group.asString());
    }
}

bool SecurityData::IsGroupForDevmode(const std::string &group) const
{
    return _groups_for_devmode.find(group) != _groups_for_devmode.end();
}

void SecurityData::InitNonVolatileDirs(const char **dirs)
{
    _non_volatile_dirs.clear();

    for (const char **cur_dir = dirs; cur_dir && *cur_dir; ++cur_dir)
    {
        std::string nv_dir{*cur_dir};

        while (!nv_dir.empty() && nv_dir.back() == '/')
            nv_dir.pop_back();

        _non_volatile_dirs.emplace(std::move(nv_dir));
    }
}

bool SecurityData::IsManifestNonVolatile(const std::string &path)
{
    auto last_slash_idx = path.find_last_of("/");
    auto manifest_dir = last_slash_idx != std::string::npos
                      ? path.substr(0, last_slash_idx)
                      : "";
    return _non_volatile_dirs.find(manifest_dir) != _non_volatile_dirs.end();
}

/// @} END OF GROUP LunaServiceHubSecurity
/// @endcond
