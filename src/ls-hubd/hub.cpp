// Copyright (c) 2008-2024 LG Electronics, Inc.
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

#include "hub.hpp"
#include <string>
#include <sstream>
#include <cinttypes>
#include <cstring>
#include <algorithm>

#include <fcntl.h>
#include <sys/socket.h>
#include <libgen.h>

#include <glib.h>

#include <pbnjson.hpp>
#include <luna-service2++/error.hpp>
#include <luna-service2++/payload.hpp>

#include "uri.h"
#include "base.h"
#include "conf.hpp"
#include "utils.h"
#include "hublane.hpp"
#include "pattern.hpp"
#include "role_map.hpp"
#include "security.hpp"
#include "permission.hpp"
#include "service_permissions.hpp"
#include "permissions_map.hpp"
#include "timersource.h"
#include "client_id.hpp"
#include "client_map.hpp"
#include "signal_map.hpp"
#include "groups_map.hpp"
#include "active_role_map.hpp"
#include "active_permission_map.hpp"
#include "role.hpp"
#include "service.hpp"
#include "hub_service.hpp"

#include <fstream>
#include <iostream>
#include <systemd/sd-daemon.h>
#include <utility>

template <typename Arg, typename... Args>
void DumpToFile(std::ostream& out, Arg&& arg, Args&&... args)
{
    out << std::forward<Arg>(arg);
    using expander = int[];
    (void)expander{0, (void(out << std::endl << std::endl << std::forward<Args>(args)), 0)...};
}

#ifdef SECURITY_HACKS_ENABLED
#include "security_hacks.h"
#endif

/**
 * @cond INTERNAL
 * @defgroup LunaServiceHub The hub for LunaService
 * @ingroup  LunaServiceInternals
 * @{
 */

/* define DEBUG for some extra print statements */
#undef DEBUG

/** hub pid file */
#define HUB_LOCK_FILENAME        "ls-hubd.pid"

#define MESSAGE_TIMEOUT_GRANULARITY_MS 100  /**< glib timer granularity for message timeouts */

/** log context names. last two are configured in /etc/pmlog.d/ls-hub.conf */
#define HUB_LOG_CONTEXT          "ls-hubd"
#define HUB_LOG_CONTEXT_DEBUG    "ls-hubd.debug"
#define HUB_LOG_CONTEXT_DISTINCT "ls-hubd.distinct"

static PmLogContext pm_log_context;

char **pid_dir = NULL;                  /**< pid file directory */

char *conf_file =  NULL;

gboolean use_distinct_log_file = FALSE;     /**< true if logging should go to distinct context log file (mentioned in /etc/pmlog.d/ls-hubd.conf) */

const char * service_dir = "/tmp/";        /**< service file directory */

#define SERVICE_FILE_SUFFIX ".service"      /**< service file suffix */

typedef struct _ConnectedClients {
    GHashTable *by_unique_name; /**< hash from unique name to _ClientId */
    GHashTable *by_fd;          /**< hash from fd to _ClientId */
} _ConnectedClients;

extern char **environ;

static GHashTable *pending = NULL;              /**< hash of service name to _ClientId */
static GHashTable *available_services = NULL;   /**< hash of service name to _ClientId */

static _ConnectedClients connected_clients;     /**< all connected clients
                                                     TODO: may want to build this
                                                     into transport layer */

static GSList *waiting_for_service = NULL;      /**< list of messages waiting for a
                                                  service that is in the pending list;
                                                  it's assumed that this will not
                                                  happen very often, so we use a list */

/**
 * Keeps track of the state of running dynamic services
 *
 * HASH: service name to _Service ptr
 */
static GHashTable *dynamic_service_states = NULL;

/************************************************************************/
static bool _LSHubRemoveClientSignals(_LSTransportClient *client);
static void _LSHubSendSignal(_LSTransportClient *client, void *dummy, _LSTransportMessage *message);
static void _LSHubHandleSignal(_LSTransportMessage *message, bool generated_by_hub);
static void _LSHubSignalRegisterAllServicesItem(gpointer key, gpointer value, gpointer user_data);
static gchar * _LSHubSignalRegisterAllServices(GHashTable *table);

static void _LSHubSendMonitorMessage(int fd, _ClientId *id, _ClientId *monitor_id);

static bool _LSHubSendServiceWaitListReply(_ClientId *id, bool success, bool is_dynamic, LSError *lserror);

static void _LSHubAddMessageTimeout(_LSTransportMessage *message, int timeout_ms, GSourceFunc callback);
static void _LSHubRemoveMessageTimeout(_LSTransportMessage *message);

bool _DynamicServiceLaunch(_Service *service, LSError *lserror);

std::vector<std::string> GetServiceRedirectionVariants(const char* service_name)
{
    std::vector<std::string> ret;

    // For legacy Palm and LGE services see if there's corresponding com.webos.service.*
    // available.
    static auto migration_regex = mk_ptr(g_regex_new("^com\\.(palm|lge|webos)(.service)*\\.(.+)$",
                                                     GRegexCompileFlags(G_REGEX_RAW | G_REGEX_OPTIMIZE),
                                                     GRegexMatchFlags(0),
                                                     nullptr),
                                         g_regex_unref);
    GMatchInfo *match_info;
    if (g_regex_match(migration_regex.get(), service_name, GRegexMatchFlags(0), &match_info))
    {
        auto prefix = mk_ptr(g_match_info_fetch(match_info, 1), g_free);
        auto name = mk_ptr(g_match_info_fetch(match_info, 3), g_free);

        if (strcmp(prefix.get(), "webos") != 0)
        {
            // Forward compatibility for legacy clients connecting to migrated
            // services.
            ret.push_back(std::string("com.webos.service.") + name.get());
        }
        else
        {
            // Backward compatibility for new clients connecting to outdated
            // services.
            ret.push_back(std::string("com.palm.") + name.get());
            ret.push_back(std::string("com.lge.") + name.get());
            ret.push_back(std::string("com.palm.service.") + name.get());
        }
    }
    g_match_info_free(match_info);

    return ret;
}

/**
 *******************************************************************************
 * @brief Look up a client in the available services map by service name.
 *
 * @param  service_name     IN  name of service (e.g., com.palm.foo)
 *
 * @retval  _ClientId on success
 * @retval  NULL on failure
 *******************************************************************************
 */
_ClientId* AvailableMapLookup(const char* service_name)
{
    return static_cast<_ClientId*>(g_hash_table_lookup(available_services, service_name));
}

/**
 *******************************************************************************
 * @brief Look up a client in the connected clients map by unique name.
 *
 * @param  unique_name     IN  unique name of service (socket name generated by the hub)
 *
 * @retval  _ClientId on success
 * @retval  NULL on failure
 *******************************************************************************
 */
_ClientId* AvailableMapLookupByUniqueName(const char *unique_name)
{
    return static_cast<_ClientId*>(g_hash_table_lookup(connected_clients.by_unique_name, unique_name));
}

/**
 *******************************************************************************
 * @brief Add dynamic service to dynamic service state map. Hash of service name to
 * service ptr (dynamic).
 *
 * @param  service  IN  service to add
 * @param  lserror  OUT set on error
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
_DynamicServiceStateMapAdd(_Service *service, LSError *lserror)
{
    LS_ASSERT(service != NULL);
    LS_ASSERT(service->num_services == 1);
    LS_ASSERT(service->is_dynamic == true);
    LS_ASSERT(lserror != NULL);

    LOG_LS_DEBUG("%s: adding service name: \"%s\" to dynamic map\n",
                 __func__, service->service_names[0]);

    _ServiceRef(service);
    g_hash_table_replace(dynamic_service_states, service->service_names[0], service);
    return true;
}

/**
 *******************************************************************************
 * @brief Remove the dynamic service state from the dynamic service state map.
 *
 * @param  service  IN service (dynamic)
 *
 * @retval  true on success
 * @retval  false on failure (service not found in map)
 *******************************************************************************
 */
bool
_DynamicServiceStateMapRemove(_Service *service)
{
    LS_ASSERT(service != NULL);
    LS_ASSERT(service->num_services == 1);

    /* unref'ing of the service done by the hash table */
    if (!g_hash_table_remove(dynamic_service_states, service->service_names[0]))
    {
        return false;
    }
    return true;
}

/**
 *******************************************************************************
 * @brief Look up a dynamic service in the dynamic service state map by name.
 *
 * @param  service_name     IN  name of dynamic service (e.g., com.palm.foo)
 *
 * @retval  service on success
 * @retval  NULL on failure
 *******************************************************************************
 */
_Service*
_DynamicServiceStateMapLookup(const char *service_name)
{
    LS_ASSERT(service_name != NULL);
    return static_cast<_Service *>(g_hash_table_lookup(dynamic_service_states, service_name));
}

/**
 *******************************************************************************
 * @brief Reap a spawned child process that was dynamically launched.
 *
 * @param  pid      IN  pid of process that exited
 * @param  status   IN  status of process that exited
 * @param  service  IN  dynamic service
 *******************************************************************************
 */
void
_DynamicServiceReap(GPid pid, gint status, _Service *service)
{
    LS_ASSERT(service != NULL);
    LS_ASSERT(service->is_dynamic == true);

    /* TODO: query exit status of process with WIFEXITED, WEXITSTATUS,
     * etc. See waitpid(2) */
    service->state = _DynamicServiceStateStopped;

    g_spawn_close_pid(pid);
    service->pid = 0;

    LOG_LS_DEBUG("%s: Reaping dynamic service: service: %p, pid: %d, exit status: %d, state: %d", __func__, service, pid, status, service->state);
    //_ServicePrint(service);

    if (service->respawn_on_exit)
    {
        LSError lserror;
        LSErrorInit(&lserror);

        service->respawn_on_exit = false;

        if (!_DynamicServiceLaunch(service, &lserror))
        {
            LOG_LSERROR(MSGID_LSHUB_SERVICE_LAUNCH_ERR, &lserror);
            LSErrorFree(&lserror);
        }
    }

    if (service->state == _DynamicServiceStateStopped)
    {
        /* Remove from state map since we're not running anymore */
        _DynamicServiceStateMapRemove(service);
    }

    _ServiceUnref(service);  /* ref from child_watch_add */
}


/**
 * Reset the OOM settings on spawned procs, since ls-hubd's oom_score_adj is set to -1000
 * and dynamic services are inheriting that setting, which we do not want.
 */
static void
ResetOomSettings(pid_t pid)
{
    char fn[24];
    int  oomf;

    snprintf(fn, 23, "/proc/%d/oom_adj", pid);
    oomf = open(fn, O_RDWR);
    if (oomf >= 0)
    {
        G_GNUC_UNUSED auto num_written = write(oomf, "0", 1);
        close(oomf);
    }
}

/**
 *******************************************************************************
 * @brief Launch a dynamic service.
 *
 * @param  service  IN  dynamic service to launch
 * @param  lserror  OUT set on error
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
_DynamicServiceLaunch(_Service *service, LSError *lserror)
{
    LS_ASSERT(service != NULL);
    LS_ASSERT(service->is_dynamic == true);

    int argc = 0;

    /* Debug */
    //_ServicePrint(service);

    if (service->state == _DynamicServiceStateSpawned)
    {
        /* someone else already spawned the service, so don't do anything
         * and wait for it to come up */
        return true;
    }
    else if (service->state == _DynamicServiceStateRunningDynamic)
    {
        /* service requested in the time frame between when it unregistered
         * from the bus and when we reaped the process. */
        service->respawn_on_exit = true;
        return true;
    }
    else if (service->state == _DynamicServiceStateRunning)
    {
        LOG_LS_ERROR(MSGID_LSHUB_SERV_RUNNING, 1,
                     PMLOGKS("APP_ID", service->exec_path),
                     "Service is running, but _DynamicServiceLaunch was called");
        return false;
    }

    service->state = _DynamicServiceStateSpawned;

    /* parse the exec string into arguments */
    GErrorPtr gerror;
    char** targv = nullptr;
    auto argv = mk_ptr<char**>(&targv, [] (char*** arg) {g_strfreev(*arg);});
    if (!g_shell_parse_argv(service->exec_path, &argc, argv.get(), gerror.pptr()))
    {
        _LSErrorSet(lserror, MSGID_LSHUB_ARGUMENT_ERR, -1,
                    "Error parsing arguments, string: \"%s\", message: \"%s\"\n", service->exec_path, gerror->message);
        return false;
    }


    std::string service_names_str;

    for (int i = 0; i < service->num_services; i++)
    {
        service_names_str += service->service_names[i];
        service_names_str += ";";
    }

    /* Append to the hub's environment. There could be an issue if you set
     * either of the above env variables in the hub itself (duplicate keys),
     * but that shouldn't happen  */
    gchar **envp = g_get_environ ();
    if(envp != NULL)
    {
        envp = g_environ_setenv(envp,"LS_SERVICE_NAMES",service_names_str.c_str(),TRUE);
        envp = g_environ_setenv(envp,"LS_SERVICE_FILE_NAME",service->service_file_name,TRUE);
    }

    /* TODO: modify arguments, esp. stdin, stdout, stderr */
    bool ret = g_spawn_async_with_pipes(NULL,  /* inherit parent's working dir */
                             *argv.get(), /* argv */
                             envp, /* environment -- NULL means inherit parent's env */
                             G_SPAWN_DO_NOT_REAP_CHILD, /* flags */
                             NULL, /* child_setup */
                             NULL, /* user_data */
                             &service->pid,    /* child_pid */
                             NULL, /* stdin */
                             NULL, /* stdout */
                             NULL, /* stderr */
                             gerror.pptr());

    if (!ret)
    {
        _LSErrorSet(lserror, MSGID_LSHUB_SPAWN_ERR, -1,
                    "Error attemtping to launch service: \"%s\"\n", gerror->message);
        return false;
    }

    ResetOomSettings(service->pid);

    /* set up child watch so we can reap the child */
    _ServiceRef(service);
    g_child_watch_add(service->pid, (GChildWatchFunc)_DynamicServiceReap, service);
    g_strfreev(envp);
    return ret;
}

/**
 *******************************************************************************
 * @brief Find and launch a dynamic service given a service name.
 *
 * @param  service_name     IN  name of service to launch
 * @param  client           IN  client requesting the dynamic service
 * @param  requester_app_id IN  app id that is requesting the launch (for
 *                              debugging bad requests from apps)
 * @param  lserror          OUT set on error
 *
 * @retval  true if dynamic service was found and successfully launched
 * @retval  false on failure
 *******************************************************************************
 */
bool
_DynamicServiceFindandLaunch(const char *service_name, const _LSTransportClient *client, const char *requester_app_id, LSError *lserror)
{
    /* Check to see if this dynamic service is in one of the service files */
    _Service *service = SecurityData::CurrentSecurityData().services.Lookup(service_name);

    if (service)
    {
        LS_ASSERT(service->is_dynamic == true);

        /* Check to see if the service state is already being tracked */
        _Service *service_state = _DynamicServiceStateMapLookup(service_name);

        if (!service_state)
        {
            /* Create a new service state */
            service_state = _ServiceNewRef(&service_name, 1, service->exec_path, true, service->service_file_name);
            if (!_DynamicServiceStateMapAdd(service_state, lserror))
            {
                _ServiceUnref(service_state);
                return false;
            }
            _ServiceUnref(service_state);
        }

        return _DynamicServiceLaunch(service_state, lserror);
    }

    const _LSTransportCred *cred = _LSTransportClientGetCred(client);
    pid_t requester_pid = _LSTransportCredGetPid(cred);
    const char *requester_exe = _LSTransportCredGetExePath(cred);

    _LSErrorSet(lserror, MSGID_LSHUB_NO_DYNAMIC_SERVICE, -1, "service: \"%s\" not found in dynamic service set (requester pid: " LS_PID_PRINTF_FORMAT ", requester exe: \"%s\", requester app id: \"%s\"\n",
                service_name,
                LS_PID_PRINTF_CAST(requester_pid), requester_exe ? requester_exe : "(null)",
                requester_app_id ? requester_app_id : "(null)");
    return false;
}

/**
 *******************************************************************************
 * @brief Set the state of a dynamic service.
 *
 * @param  service          IN  dynamic service
 * @param  state            IN  state
 *
 * @retval true on success
 * @retval false otherwise
 *******************************************************************************
 */
bool
_DynamicServiceSetState(_Service *service, _DynamicServiceState state)
{
    LS_ASSERT(service != NULL);
    LS_ASSERT(service->is_dynamic == true);

    service->state = state;

    return true;
}


/**
 *******************************************************************************
 * @brief Get the state of a dynamic service.
 *
 * @param  service  IN  dynamic service
 *
 * @retval  state
 *******************************************************************************
 */
_DynamicServiceState
_DynamicServiceGetState(_Service *service)
{
    LS_ASSERT(service != NULL);
    LS_ASSERT(service->is_dynamic == true);

    return service->state;
}

/**
 *******************************************************************************
 * @brief Allocate and initialize a service map.
 *
 * @param  service_map     IN  map
 * @param  lserror         OUT set on error
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
_ServiceInitMap(GHashTable **service_map, LSError *lserror)
{
    LS_ASSERT(service_map != NULL);

    /* destroy the old service map -- any items in use are
     * ref-counted and will still exist after this call */
    if (*service_map)
    {
        g_hash_table_destroy(*service_map);
    }

    /* create the new map */
    *service_map = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, (GDestroyNotify)_ServiceUnref);

    return true;
}

/**
 *******************************************************************************
 * @brief Initialize the dynamic service map that contains service states.
 *
 * @param  lserror  OUT set on error
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
DynamicServiceInitStateMap(LSError *lserror)
{
    return _ServiceInitMap(&dynamic_service_states, lserror);
}

/**
 *******************************************************************************
 * @brief Send a signal to all registered clients that the config file scanning
 * is complete
 *******************************************************************************
 */
void LSHubSendConfScanCompleteSignal()
{
    /*
     * Initial config parsing happens before the hub gets initialized,
     * so we don't have any subscribers or signal map. Let's
     * just ignore this call
     */
    if (!signal_map) return;

    char payload[] = "{\"returnValue\": true, \"status\": \"scan complete\"}";

    _LSTransportMessage *message = LSTransportMessageSignalNewRef(HUB_CONTROL_CATEGORY, HUB_CONF_SCAN_COMPLETE_METHOD, payload, false);
    _LSHubHandleSignal(message, true);
    message->raw->header.is_public_bus = true;
    _LSHubHandleSignal(message, true);
    _LSTransportMessageUnref(message);
}


/**
 ********************************************************************************
 * @brief Send a signal to all registered clients that a service is up or
 * down.
 *
 * Don't use this directly. Instead use @ref _LSHubSendServiceDownSignal and
 * @ref _LSHubSendServiceUpSignal.
 *
 * @param  service_name     IN   common name of service changing state (e.g., com.palm.foo)
 * @param  unique_name      IN   unique name of service changing state
 * @param  service_pid      IN   pid of executable that registered service (might be 0), only used if service is coming up
 * @param  all_names        IN   JSON fragment placed inside an array, listed all service names that might be used by executable,
                                 only used if service is coming up
 * @param  up               IN   true if service is coming up, false otherwise
 * @param  is_public_bus    IN
 ********************************************************************************/
static void
_LSHubSendServiceUpDownSignal(const char *service_name, const char *unique_name, pid_t service_pid, const char * all_names, bool up, bool is_public_bus)
{
    LS_ASSERT(service_name != NULL);
    LS_ASSERT(unique_name != NULL);

    char *payload = NULL;

    if (up)
    {
        payload = g_strdup_printf(SERVICE_STATUS_UP_PAYLOAD, service_name, unique_name, service_pid, all_names ? all_names : "");
    }
    else
    {
        payload = g_strdup_printf(SERVICE_STATUS_DOWN_PAYLOAD, service_name, unique_name);
    }

    _LSTransportMessage *message = LSTransportMessageSignalNewRef(SERVICE_STATUS_CATEGORY, service_name, payload, is_public_bus);

    /* send out this "special" status signal to registered clients */
    if (up)
    {
        _LSTransportMessageSetType(message, _LSTransportMessageTypeServiceUpSignal);
    }
    else
    {
        _LSTransportMessageSetType(message, _LSTransportMessageTypeServiceDownSignal);
    }

    _LSHubHandleSignal(message, true);
    _LSTransportMessageUnref(message);

    g_free(payload);
}

/**
 ********************************************************************************
 * @brief Send a signal to all registered clients that a service is down.
 *
 * @param  service_name     IN   common name of service going down (e.g.,
 * com.palm.foo)
 * @param  unique_name      IN   unique name of service going down
 ********************************************************************************
 */
static void
_LSHubSendServiceDownSignal(const char *service_name, const char *unique_name)
{
    _LSHubSendServiceUpDownSignal(service_name, unique_name, 0, NULL, false, false);
    _LSHubSendServiceUpDownSignal(service_name, unique_name, 0, NULL, false, true);
}

/**
 ********************************************************************************
 * @brief Send a signal to all registered clients that a service is up.
 *
 * @param service_name  IN common name of service coming up (e.g.,
 *                        com.palm.foo)
 * @param unique_name   IN   unique name of service coming up
 * @param service_pid   IN service pid
 * @param all_names     IN @see _LSHubSendServiceUpDownSignal
 * @param is_public_bus IN true if bus is public
 *******************************************************************************
 */
static void
_LSHubSendServiceUpSignal(const char *service_name, const char *unique_name, pid_t service_pid, const char *all_names,
                          bool is_public_bus, bool is_old_format = false)
{

    _LSHubSendServiceUpDownSignal(service_name, unique_name, service_pid, all_names, true, is_public_bus);
    if (!is_old_format)
    {
        _LSHubSendServiceUpDownSignal(service_name, unique_name, service_pid, all_names, true, true);
    }
}

/**
 *******************************************************************************
 * @brief Handle a client that is disconnecting.
 *
 * @param client   IN client that is going away
 * @param type     IN type of disconnect (clean, dirty, etc.)
 * @param context  IN unused
 *******************************************************************************
 */
void
_LSHubHandleDisconnect(_LSTransportClient *client, _LSTransportDisconnectType type, void *context)
{
    LSError lserror;
    LSErrorInit(&lserror);

    /* look up _ClientId */
    _ClientId *id = static_cast<_ClientId *>(g_hash_table_lookup(connected_clients.by_fd, GINT_TO_POINTER(client->channel.fd)));

    if (!id)
    {
        /*
         * This can happen if the name was already taken when attempting to
         * register in _LSHubHandleRequestName
         */
        LOG_LS_WARNING(MSGID_LSHUB_UNKNOWN_DISCONNECT_MESSAGE, 1,
                       PMLOGKS("APP_ID", client->service_name),
                       "We received a disconnect message for client: %p, but couldn't find it in the client map", client);
        return;
    }

    /* remove from available_services and/or pending */
    if (id->service_name != NULL)
    {
        _Service *service = SecurityData::CurrentSecurityData().services.Lookup(id->service_name);
        bool is_dynamic = service && service->is_dynamic;

        LOG_LS_DEBUG("%s: disconnecting: \"%s\"\n", __func__, id->service_name);

        /* send out a server status message to registered clients to let them know
         * that the client is down */
        _LSHubSendServiceDownSignal(id->service_name, id->local.name);
        for (const auto& name : GetServiceRedirectionVariants(id->service_name))
        {
            if (!g_hash_table_lookup(available_services, name.c_str()))
                _LSHubSendServiceDownSignal(name.c_str(), id->local.name);
        }

        if (g_conf_log_service_status)
        {
            const _LSTransportCred *cred = _LSTransportClientGetCred(client);
            G_GNUC_UNUSED pid_t pid = _LSTransportCredGetPid(cred);
            LOG_LS_DEBUG("SERVICE: ServiceDown (name: \"%s\", dynamic: %s, pid: " LS_PID_PRINTF_FORMAT ", "
                      "exe: \"%s\", cmdline: \"%s\")",
                       id->service_name, is_dynamic ? "true" : "false",
                       LS_PID_PRINTF_CAST(pid),
                       _LSTransportCredGetExePath(cred),
                       _LSTransportCredGetCmdLine(cred));
        }

        g_hash_table_remove(pending, id->service_name);
        g_hash_table_remove(available_services, id->service_name);

        /* Send a failure QueryNameReply to any service that is still
         * waiting for this service */
        if (!_LSHubSendServiceWaitListReply(id, false, is_dynamic, &lserror))
        {
            LOG_LSERROR(MSGID_LSHUB_SENDMSG_ERROR, &lserror);
            LSErrorFree(&lserror);
        }

        _Service *dynamic = _DynamicServiceStateMapLookup(id->service_name);
        if (dynamic && dynamic->state == _DynamicServiceStateRunning)
        {
            /* The service was launched manually so we'll never get the
             * _DynamicServiceReap callback */
            _DynamicServiceSetState(dynamic, _DynamicServiceStateStopped);
            //_DynamicServiceUnref(dynamic);
            _DynamicServiceStateMapRemove(dynamic);
        }
    }

    /* NOV-93826: Send out status messages for non-services as well because
     * subscriptions use this to keep track of connected clients
     *
     * In this case we set the service name to the unique name
     * for legacy compatiblity */
    _LSHubSendServiceDownSignal(id->local.name, id->local.name);

    /* Update state if the monitor is disconnecting */
    if (id->is_monitor)
    {
        LOG_LS_DEBUG("%s: monitor disconnected\n", __func__);
        id->is_monitor = false;
        _LSHubClientIdLocalUnref(monitor);
        monitor = NULL;
    }

    /* remove from connected list */
    g_hash_table_remove(connected_clients.by_fd, GINT_TO_POINTER(client->channel.fd));
    g_hash_table_remove(connected_clients.by_unique_name, id->local.name);

    /* SIGNAL: remove all instances of client from _SignalMap */
    _LSHubRemoveClientSignals(client);

#ifdef SECURITY_HACKS_ENABLED
    //we don't have trusted services in active maps
    if (_LSIsTrustedService(_LSTransportClientGetServiceName(client)))
    {
        return;
    }
#endif

    /* Remove the client from the active role map */
    if (!LSHubActiveRoleMapClientRemove(client, &lserror))
    {
        LOG_LSERROR(MSGID_LSHUB_CLIENT_ERROR, &lserror);
        LSErrorFree(&lserror);
    }

    /* Remove the client from the active permissions map */
    if (!LSHubActivePermissionMapClientRemove(client, &lserror))
    {
        LOG_LSERROR(MSGID_LSHUB_CLIENT_ERROR, &lserror);
        LSErrorFree(&lserror);
    }

    /* transport code will handle cleaning up the client and removing the watches */
}

/**
 *******************************************************************************
 * @brief Send a reply to a request name message.
 *
 * @param  client        IN  client to send reply to
 * @param  unique_name   IN  service unique name or null in case of error
 * @param  client_flags  IN  service flags
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
static void
_LSHubSendRequestNameReply(_LSTransportClient *client, const char *unique_name, int32_t client_flags)
{
    LS_ASSERT(client);

    std::string jval_str = "[]";
    std::string trust_provided_str = "[]";
    std::string trust_required_str = "[]";
    std::string trust_as_string;
    std::string service_name; // Remove later
    if (g_conf_security_enabled)
    {
        LSHubPermission *active_perm = LSHubActivePermissionMapLookup(unique_name);
        LS_ASSERT(active_perm);
        if (active_perm)
        {
            service_name = LSHubPermissionGetServiceName(active_perm);
            LOG_LS_DEBUG("%s :###### active permission found for unique_name [%s] service_name[%s]",
                __func__, unique_name, service_name.c_str());

            pbnjson::JValue jval = pbnjson::Array();
            for (const auto &category : LSHubPermissionGetProvided(active_perm))
            {
                pbnjson::JValue group_json = pbnjson::Array();
                for (const auto &group : category.second)
                {
                    group_json << pbnjson::JValue(group);
                }
                jval << (pbnjson::Object()
                         << pbnjson::JValue::KeyValue("category", category.first)
                         << pbnjson::JValue::KeyValue("groups", group_json));
            }
            //TBD: Coonsider sending trustlevels in seperate string as jval
            // Create provided trustlevel json
            pbnjson::JValue jval_trust_provided = pbnjson::Array();
            for(const auto &trust_provided : LSHubPermissionGetProvidedTrust(active_perm))
            {
                pbnjson::JValue trust_provided_json = pbnjson::Array();
                for(const auto &trust_level : trust_provided.second)
                {
                     trust_provided_json << pbnjson::JValue(trust_level);
                }
                jval_trust_provided << (pbnjson::Object()
                                            << pbnjson::JValue::KeyValue("group", trust_provided.first)
                                            << pbnjson::JValue::KeyValue("provided", trust_provided_json));
            }

            // Create required trustlevel json
            pbnjson::JValue jval_trust_required = pbnjson::Array();
            for(const auto &trust_required : LSHubPermissionGetRequiredTrust(active_perm))
            {
                pbnjson::JValue trust_required_json = pbnjson::Array();
                for(const auto &trust_level : trust_required.second)
                {
                     trust_required_json << pbnjson::JValue(trust_level);
                }
                jval_trust_required << (pbnjson::Object()
                                           << pbnjson::JValue::KeyValue("group", trust_required.first)
                                           << pbnjson::JValue::KeyValue("required", trust_required_json));
            }

            // Serialize json
            jval_str = pbnjson::JGenerator::serialize(jval, true);
            trust_provided_str = pbnjson::JGenerator::serialize(jval_trust_provided, true);
            trust_required_str = pbnjson::JGenerator::serialize(jval_trust_required, true);

            // TBD :
            // We also want to send trust level as 1 simple string .
            // We can remove or keep this later
            trust_as_string = LSHubPermissionGetRequiredTrustAsString(active_perm);
        }
    }
    else
    {
        // If security is disabled, all the API belong to the same group "TOTUM" (lat. everything),
        // and every service `requires' that group to function.
        // @cond IGNORE
        jval_str = R"([{"category":"/*", "groups":["TOTUM"]}])";
        // Untile every service migrates to enhanced ACG, we should not enable this
        // trust_provided_str = R"([{"group":"/*", "provided":["TOTUM"]}])";
        // @endcond
    }

    auto reply = mk_ptr(_LSTransportMessageNewRef(LS_TRANSPORT_MESSAGE_DEFAULT_PAYLOAD_SIZE), _LSTransportMessageUnref);
    _LSTransportMessageSetType(reply.get(), _LSTransportMessageTypeRequestNameReply);

    _LSTransportMessageIter iter;
    _LSTransportMessageIterInit(reply.get(), &iter);
    if (!_LSTransportMessageAppendInt32(&iter, LS_TRANSPORT_REQUEST_NAME_SUCCESS)
        || !_LSTransportMessageAppendBool(&iter, LSHubClientGetPrivileged(client))
        || !_LSTransportMessageAppendBool(&iter, LSHubClientGetProxy(client))
        || !_LSTransportMessageAppendString(&iter, unique_name)
        || !_LSTransportMessageAppendString(&iter, jval_str.c_str())
        || !_LSTransportMessageAppendString(&iter, trust_provided_str.c_str())
        || !_LSTransportMessageAppendString(&iter, trust_required_str.c_str())
        || !_LSTransportMessageAppendString(&iter, trust_as_string.c_str())
        || !_LSTransportMessageAppendInt32(&iter, client_flags)
        || !_LSTransportMessageAppendInvalid(&iter))
    {
        LOG_LS_ERROR(MSGID_LS_OOM_ERR, 0, "%s", LS_ERROR_TEXT_OOM);
        return;
    }

    if((strstr(trust_provided_str.c_str(), "[]") == NULL) &&
        (strstr(trust_required_str.c_str(), "[]") == NULL))
    {
        std::ofstream file;
        std::string name = "/tmp/" + std::string("hub_LSHubSendRequestNameReply" + service_name);
        file.open(name);
        if(file.is_open())
        {
           DumpToFile(file, trust_provided_str, trust_required_str, trust_as_string);
           file.close();
        }
    }

    LOG_LS_DEBUG("%s : trust_provided_str.c_str() [ %s ]", __func__, trust_provided_str.c_str());
    LS::Error lserror;
    if (!_LSTransportSendMessage(reply.get(), client, nullptr, lserror.get()))
    {
        LOG_LSERROR(MSGID_LSHUB_SENDMSG_ERROR, lserror);
    }
}

/**
 *******************************************************************************
 * @brief Send an error reply to a request name message.
 *
 * @param  client   IN  client to send reply
 * @param  err_code IN  numeric error code (0 means success)
 *
 *******************************************************************************
 */
static void
_LSHubSendRequestNameError(_LSTransportClient *client, long err_code)
{
    LS_ASSERT(client);

    auto reply = mk_ptr(_LSTransportMessageNewRef(LS_TRANSPORT_MESSAGE_DEFAULT_PAYLOAD_SIZE), _LSTransportMessageUnref);
    _LSTransportMessageSetType(reply.get(), _LSTransportMessageTypeRequestNameReply);

    _LSTransportMessageIter iter;
    _LSTransportMessageIterInit(reply.get(), &iter);
    if (!_LSTransportMessageAppendInt32(&iter, err_code) ||
        !_LSTransportMessageAppendInvalid(&iter))
    {
        LOG_LS_ERROR(MSGID_LS_OOM_ERR, 0, "%s", LS_ERROR_TEXT_OOM);
        return;
    }

    LS::Error lserror;
    if (!_LSTransportSendMessage(reply.get(), client, NULL, lserror.get()))
    {
        LOG_LSERROR(MSGID_LSHUB_SENDMSG_ERROR, lserror);
    }
}

static
std::string _CreateUniqueName()
{
    static auto randchar = []() -> char
    {
        static const char charset[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

        return charset[rand() % (sizeof(charset) - 1)];
    };

    std::string generated(8, 0);
    do
    {
        std::generate_n(generated.begin(), generated.size(), randchar);
    } while(g_hash_table_contains(connected_clients.by_unique_name, generated.c_str()));

    return generated;
}

/**
 *******************************************************************************
 * @brief Handle a "RequestName" message for a local connection
 *
 * @param  message  IN  request name message
 *
 * @return FALSE if client isn't allowed to register requested name
 *         (for instance, by security reasons)
 *         TRUE if succeeded.
 *******************************************************************************
 */
static bool
_LSHubHandleRequestName(_LSTransportMessage *message)
{
    _LSTransportClient *client = _LSTransportMessageGetClient(message);
    if (!client)
    {
        LOG_LS_ERROR(MSGID_LSHUB_NO_CLIENT, 0, "Unable to get client from message");
        return false;
    }

    _LSTransportMessageIter iter;
    _LSTransportMessageIterInit(message, &iter);

    int32_t protocol_version = 0;
    if (!_LSTransportMessageGetInt32(&iter, &protocol_version))
    {
        LOG_LS_ERROR(MSGID_LS_MSG_ERR, 0, "FIXME!");
    }

    if (protocol_version != LS_TRANSPORT_PROTOCOL_VERSION)
    {
        LOG_LS_ERROR(MSGID_LSHUB_WRONG_PROTOCOL, 0,
                     "Transport protocol mismatch. Client version: %d. Hub version: %d",
                     protocol_version, LS_TRANSPORT_PROTOCOL_VERSION);

        _LSHubSendRequestNameError(client, LS_TRANSPORT_REQUEST_NAME_INVALID_PROTOCOL_VERSION);
        return false;
    }

    /* get service name */
    const char *service_name = nullptr;
    _LSTransportMessageIterNext(&iter);
    _LSTransportMessageGetString(&iter, &service_name);

    /* get application id */
    const char *app_id = nullptr;
    _LSTransportMessageIterNext(&iter);
    _LSTransportMessageGetString(&iter, &app_id);

    LOG_LS_DEBUG("%s: service_name: \"%s\" app_id: \"%s\"\n", __func__, service_name, app_id);

    // If peer specified application Id do checking if it is an application container
    // Do now allow regular executables to request services by application Id
    if (app_id && !LSHubIsClientApplicationContainer(client))
    {
        _LSHubSendRequestNameError(client, LS_TRANSPORT_REQUEST_NAME_PERMISSION_DENIED);
        return false;
    }
    else if (app_id)
    {
        _LSTransportClientSetApplicationId(client, app_id);
    }

    /* Check security permissions and service source*/
    int32_t client_flags = _LSTransportFlagNoFlags;
    LSError lserror;
    LSErrorInit(&lserror);
    if (!LSHubIsClientAllowedToRequestName(client, service_name, client_flags))
    {
        /* Remove the client from the active role map */
        if (!LSHubActiveRoleMapClientRemove(client, &lserror))
        {
            LOG_LSERROR(MSGID_LSHUB_CLIENT_ERROR, &lserror);
            LSErrorFree(&lserror);
        }

        _LSHubSendRequestNameError(client, LS_TRANSPORT_REQUEST_NAME_PERMISSION_DENIED);
        return false;
    }

    /* look up requested name and make sure that it's not already in use */
    if (service_name && (g_hash_table_lookup(pending, service_name) ||
                         g_hash_table_lookup(available_services, service_name)))
    {
        /* Remove the client from the active role map */
        if (!LSHubActiveRoleMapClientRemove(client, &lserror))
        {
            LOG_LSERROR(MSGID_LSHUB_CLIENT_ERROR, &lserror);
            LSErrorFree(&lserror);
        }

        _LSHubSendRequestNameError(client, LS_TRANSPORT_REQUEST_NAME_NAME_ALREADY_REGISTERED);
        return false;
    }

    /* generate a unique name */
    std::string unique_name = _CreateUniqueName();

    LS_ASSERT(!_LSTransportClientGetUniqueName(client));
    _LSTransportClientSetUniqueName(client, g_strdup(unique_name.c_str()));

    LOG_LS_DEBUG("%s: unique_name: \"%s\"\n", __func__, unique_name.c_str());

    /* add client id to client lookup (refs client) */
    auto id = mk_ptr(_LSHubClientIdLocalNewRef(service_name, unique_name.c_str(), client),
                     _LSHubClientIdLocalUnref);

    /* add unique name to pending hash if they are registering a service name */
    if (id->service_name)
    {
        _LSHubClientIdLocalRef(id.get());
        g_hash_table_replace(pending, id->service_name, id.get());
    }

    /* hash clientId with fd as key */
    _LSHubClientIdLocalRef(id.get());
    g_hash_table_replace(connected_clients.by_fd, GINT_TO_POINTER(client->channel.fd), id.get());

    /* hash clientId with unique name as key */
    _LSHubClientIdLocalRef(id.get());
    g_hash_table_replace(connected_clients.by_unique_name, id->local.name, id.get());

#ifdef SECURITY_HACKS_ENABLED
    if (_LSIsTrustedService(service_name))
    {
        LOG_LS_INFO(MSGID_LS_NOT_AN_ERROR, 0, "Security hacks were applied for: %s", service_name);
    }
    else
    {
#endif
        LS::Error error;
        if (!LSHubActivePermissionMapClientAdd(client, id->service_name, unique_name.c_str(), error))
        {
            LOG_LSERROR(MSGID_LSHUB_CLIENT_ERROR, error.get());
        }
#ifdef SECURITY_HACKS_ENABLED
    }
#endif

    _LSHubSendRequestNameReply(client, unique_name.c_str(), client_flags);
    return true;
}

static std::string
_LSHubGetRequiredTrustsByName(const char *origin_exe, const char *origin_id, const char *origin_name) {

    const LSHubRole *role = nullptr;
    if (origin_id) {
        // look-up in all roles by app-id
        role = SecurityData::CurrentSecurityData().roles.Lookup(origin_id);
    } else if (origin_exe) {
        role = SecurityData::CurrentSecurityData().roles.Lookup(origin_exe);
    }

    bool is_devmode = !role || LSHubRoleGetType(role) == LSHubRoleTypeDevmode;
    pbnjson::JValue jval = pbnjson::Array();
    std::string trust;

    {
        GroupsMap &groups = SecurityData::CurrentSecurityData().groups;
        trust = groups.GetRequiredTrustAsString(origin_name);
        LOG_LS_DEBUG("[%s] trust: %s \n", __func__, trust.c_str());
        {
            jval << pbnjson::JValue(trust);
        }
    }

    std::string jval_str = pbnjson::JGenerator::serialize(jval, true);
    if (!g_conf_security_enabled) {
        // If security is disabled, all the API belong to the same group "TOTUM" (lat. everything),
        // and every service `requires' that group to function.
        jval_str = R"(["TOTUM"])";
    }
    return trust;
}

static std::string
_LSHubGetRequiredTrusts(const _LSTransportClient *client)
{
    // TBD: Reply with required trustlevels
    LS_ASSERT(client != NULL);
    // Get effective LSHubPermission for client
    LSHubPermission *active_perm = LSHubActivePermissionMapLookup(client);
    const char *client_name = _LSTransportClientGetServiceName(client);
#ifdef SECURITY_HACKS_ENABLED
    if (_LSIsTrustedService(client_name))
    {
        LOG_LS_INFO(MSGID_LS_NOT_AN_ERROR, 0, "Security hacks were applied for: %s", client_name);
    }
    else
#endif
    if (!active_perm)
    {
    LOG_LS_INFO(MSGID_LS_QNAME_ERR, 0,
            "Failed to find effective trusts for service %s",
            client_name);
        return "";
    }

    // Ensure restricted in devmode agents (like luna-send-pub) can't call private API.
    const LSHubRole *role = nullptr;
    if (client->app_id)
    {
        // look-up in all roles by app-id
        role = SecurityData::CurrentSecurityData().roles.Lookup(client->app_id);
    }
    else
    {
        role = LSHubActiveRoleMapLookup(_LSTransportCredGetPid(_LSTransportClientGetCred(client)));
    }

    bool is_devmode = !role || LSHubRoleGetType(role) == LSHubRoleTypeDevmode;
    pbnjson::JValue jval = pbnjson::Array();
    std::string trust;

#ifdef SECURITY_HACKS_ENABLED
    if (active_perm)
    {
#endif
    // Client will be having only 1 trust level
    //for (const auto& trust : LSHubPermissionGetRequiredTrust(active_perm))
    {
       trust = LSHubPermissionGetRequiredTrustAsString(active_perm);
       LOG_LS_DEBUG("[%s] trust: %s \n", __func__, trust.c_str());
       {
           jval << pbnjson::JValue(trust);
       }
    }
#ifdef SECURITY_HACKS_ENABLED
    }
#endif
    std::string jval_str = pbnjson::JGenerator::serialize(jval, true);
    if (!g_conf_security_enabled)
    {
        // If security is disabled, all the API belong to the same group "TOTUM" (lat. everything),
        // and every service `requires' that group to function.
        jval_str = R"(["TOTUM"])";
    }
    return trust;
}

static std::string
_LSHubGetRequiredGroupsByName(const char *origin_exe, const char *origin_id, const char *origin_name) {
    // Ensure restricted in devmode agents (like luna-send-pub) can't call private API.
    const LSHubRole *role = nullptr;
    if (origin_id) {
        // look-up in all roles by app-id
        role = SecurityData::CurrentSecurityData().roles.Lookup(origin_id);
    } else if (origin_exe) {
        role = SecurityData::CurrentSecurityData().roles.Lookup(origin_exe);
    }

    bool is_devmode = !role || LSHubRoleGetType(role) == LSHubRoleTypeDevmode;

    pbnjson::JValue jval = pbnjson::Array();

    GroupsMap &groups = SecurityData::CurrentSecurityData().groups;
    for (const auto &group : groups.GetRequired(origin_name)) {
        if (is_devmode && !SecurityData::CurrentSecurityData().IsGroupForDevmode(group))
            continue;
        jval << pbnjson::JValue(group);
    }

    std::string jval_str = pbnjson::JGenerator::serialize(jval, true);
    if (!g_conf_security_enabled) {
        // If security is disabled, all the API belong to the same group "TOTUM" (lat. everything),
        // and every service `requires' that group to function.
        jval_str = R"(["TOTUM"])";
    }

    return jval_str;
}

static std::string
_LSHubGetRequiredGroups(const _LSTransportClient *client)
{
    LS_ASSERT(client != NULL);

    // Get effective LSHubPermission for client
    LSHubPermission *active_perm = LSHubActivePermissionMapLookup(client);
    const char *client_name = _LSTransportClientGetServiceName(client);
#ifdef SECURITY_HACKS_ENABLED
    if (_LSIsTrustedService(client_name))
    {
        LOG_LS_INFO(MSGID_LS_NOT_AN_ERROR, 0, "Security hacks were applied for: %s", client_name);
    }
    else
#endif
    if (!active_perm)
    {
        // The situation is expected. Service, that is being connected to, has already stopped.
        // The message is left for a while. In the future should be moved to debug level
        LOG_LS_INFO(MSGID_LS_QNAME_ERR, 0,
            "Failed to find effective security groups for service %s",
            client_name);
        return "";
    }

    // Ensure restricted in devmode agents (like luna-send-pub) can't call private API.
    const LSHubRole *role = nullptr;
    if (client->app_id)
    {
        // look-up in all roles by app-id
        role = SecurityData::CurrentSecurityData().roles.Lookup(client->app_id);
    }
    else
    {
        role = LSHubActiveRoleMapLookup(_LSTransportCredGetPid(_LSTransportClientGetCred(client)));
    }

    bool is_devmode = !role || LSHubRoleGetType(role) == LSHubRoleTypeDevmode;

    pbnjson::JValue jval = pbnjson::Array();
#ifdef SECURITY_HACKS_ENABLED
    if (active_perm)
    {
#endif
    for (const auto &group : LSHubPermissionGetRequired(active_perm))
    {
        if (is_devmode && !SecurityData::CurrentSecurityData().IsGroupForDevmode(group))
            continue;
        jval << pbnjson::JValue(group);
    }
#ifdef SECURITY_HACKS_ENABLED
    }
#endif
    std::string jval_str = pbnjson::JGenerator::serialize(jval, true);
    if (!g_conf_security_enabled)
    {
        // If security is disabled, all the API belong to the same group "TOTUM" (lat. everything),
        // and every service `requires' that group to function.
        jval_str = R"(["TOTUM"])";
    }

    return jval_str;
}

static std::string
_LSHubGetRequiredTrustLevelAsString(const _LSTransportClient *client)
{
    std::string retVal = _LSTransportClientGetTrustString(client);
    std::string serviceName = _LSTransportClientGetServiceName(client);
    std::string appId = _LSTransportClientGetApplicationId(client);
    return retVal;
}

static bool
_LSHubSendQueryProxyNameReplyMessage(_LSTransportClient *client, const _LSTransportClient *source_client,
                                     bool is_public_bus, long err_code, const char *service_name,
                                     const char *unique_name, const char *app_id, bool is_dynamic,
                                     int fd, _LSTransportClientPermissions client_permissions, LSError *lserror,
                                     const char *origin_exe, const char *origin_id, const char *origin_name,
                                     const _LSTransportClient *origin_client, bool to_proxy_service) {

    _LSTransportMessage *reply_message = _LSTransportMessageNewRef(LS_TRANSPORT_MESSAGE_DEFAULT_PAYLOAD_SIZE);

    do {
        if (NULL == reply_message) {
            _LSErrorSetOOM(lserror);
            break;
        }

        reply_message->raw->header.is_public_bus = is_public_bus;
        _LSTransportMessageSetType(reply_message, _LSTransportMessageTypeQueryProxyNameReply);

        _LSTransportMessageIter iter;
        _LSTransportMessageIterInit(reply_message, &iter);

        std::string groups;
        std::string trusts;

        if (!_LSTransportMessageAppendInt32(&iter, err_code) ||
            !_LSTransportMessageAppendString(&iter, service_name) ||
            !_LSTransportMessageAppendString(&iter, unique_name) ||
            !_LSTransportMessageAppendInt32(&iter, is_dynamic) ||
            !_LSTransportMessageAppendString(&iter, origin_name)) {
            _LSErrorSetOOM(lserror);
            break;
        }

        if (to_proxy_service) {
            if (!_LSTransportMessageAppendString(&iter, origin_exe) ||
                !_LSTransportMessageAppendString(&iter, origin_id)) {
                _LSErrorSetOOM(lserror);
                break;
            }

            groups = source_client ? _LSHubGetRequiredGroups(source_client) : "";
            trusts = source_client ? _LSHubGetRequiredTrusts(source_client) : "";

        } else {
            if (!_LSTransportMessageAppendString(&iter, NULL) ||
                !_LSTransportMessageAppendString(&iter, NULL)) {
                _LSErrorSetOOM(lserror);
                break;
            }

            groups = origin_client ? _LSHubGetRequiredGroups(origin_client) :
                                     _LSHubGetRequiredGroupsByName(origin_exe, origin_id, origin_name);
            trusts = origin_client? _LSHubGetRequiredTrusts(origin_client) :
                                     _LSHubGetRequiredTrustsByName(origin_exe, origin_id, origin_name);
        }

        //TBD: Below line is crashing :(
        //std::string required_trust_as_string = source_client ? _LSHubGetRequiredTrustLevelAsString(source_client) : std::string("dev");

        LOG_LS_DEBUG("%s : trusts : %s", __func__, trusts.c_str());
        //LOG_LS_DEBUG("%s : required_trust_as_string : %s", __func__, required_trust_as_string.c_str());
        // TBD: We need  to add trust level here the client has
        if (err_code == LS_TRANSPORT_QUERY_NAME_SUCCESS &&
            (!_LSTransportMessageAppendString(&iter, app_id) ||
             !_LSTransportMessageAppendString(&iter, groups.c_str()) ||
             !_LSTransportMessageAppendInt32(&iter, client_permissions) ||
             !_LSTransportMessageAppendString(&iter, trusts.c_str()) ||
             !_LSTransportMessageAppendString(&iter, trusts.c_str()) ||
             !_LSTransportMessageAppendInvalid(&iter))) {
            _LSErrorSetOOM(lserror);
            break;
        }

        if (err_code != LS_TRANSPORT_QUERY_NAME_SUCCESS) {
             LOG_LS_WARNING(MSGID_LSHUB_NO_SERVICE, 0,
                            "%s: Failed Connecting to Service err_code: %ld, service_name: \"%s\", unique_name: \"%s\", %s, fd %d\n",
                            __func__, err_code, service_name, unique_name,
                            is_dynamic ? "dynamic" : "static", fd);
        }

        LOG_LS_DEBUG("%s: err_code: %ld, service_name: \"%s\", unique_name: \"%s\", %s, fd %d, groups: \"%s\"\n",
                     __func__, err_code, service_name, unique_name,
                     is_dynamic ? "dynamic" : "static", fd, groups.c_str());

        // Set the connection fd on the message (-1 on error)
        _LSTransportMessageSetFd(reply_message, fd);

        if (!_LSTransportSendMessage(reply_message, client, NULL, lserror)) {
            break;
        }

        _LSTransportMessageUnref(reply_message);
        return true;
    } while (false);

    if (reply_message) _LSTransportMessageUnref(reply_message);
    return false;
}

static bool
_LSHubSendQueryNameReplyMessage(_LSTransportClient *client, const _LSTransportClient *source_client,
                                bool is_public_bus, long err_code, const char *service_name,
                                const char *unique_name, const char *app_id, bool is_dynamic,
                                int fd, _LSTransportClientPermissions client_permissions, LSError *lserror)
{
    _LSTransportMessage *reply_message = _LSTransportMessageNewRef(LS_TRANSPORT_MESSAGE_DEFAULT_PAYLOAD_SIZE);

    do {
        if (NULL == reply_message) {
            _LSErrorSetOOM(lserror);
            break;
        }

        reply_message->raw->header.is_public_bus = is_public_bus;
        _LSTransportMessageSetType(reply_message, _LSTransportMessageTypeQueryNameReply);

        _LSTransportMessageIter iter;
        _LSTransportMessageIterInit(reply_message, &iter);

        if (!_LSTransportMessageAppendInt32(&iter, err_code) ||
            !_LSTransportMessageAppendString(&iter, service_name) ||
            !_LSTransportMessageAppendString(&iter, unique_name) ||
            !_LSTransportMessageAppendInt32(&iter, is_dynamic))
        {
            _LSErrorSetOOM(lserror);
            break;
        }

        std::string groups = source_client ? _LSHubGetRequiredGroups(source_client) : "";
        std::string trusts = source_client ? _LSHubGetRequiredTrusts(source_client) : "";

        const char *exe_path = NULL;

        if ((err_code == LS_TRANSPORT_QUERY_NAME_SUCCESS) &&
            (LSHubClientGetPrivileged(client) || LSHubClientGetProxy(client))) {
            exe_path = _LSTransportCredGetExePath(_LSTransportClientGetCred(source_client));
        }

        //TBD: Below line is crashing :(
        //std::string required_trust_as_string = source_client ? _LSHubGetRequiredTrustLevelAsString(source_client) : std::string("dev");

        LOG_LS_DEBUG("%s : trusts : %s", __func__, trusts.c_str());
        //LOG_LS_DEBUG("%s : required_trust_as_string : %s", __func__, required_trust_as_string.c_str());
        // TBD: We need  to add trust level here the client has
        if (err_code == LS_TRANSPORT_QUERY_NAME_SUCCESS &&
            (!_LSTransportMessageAppendString(&iter, app_id) ||
             !_LSTransportMessageAppendString(&iter, groups.c_str()) ||
             !_LSTransportMessageAppendInt32(&iter, client_permissions) ||
             !_LSTransportMessageAppendString(&iter, trusts.c_str()) ||
             !_LSTransportMessageAppendString(&iter, trusts.c_str()) ||
             !_LSTransportMessageAppendString(&iter, exe_path) ||
             !_LSTransportMessageAppendInvalid(&iter)))
        {
            _LSErrorSetOOM(lserror);
            break;
        }

        if (err_code != LS_TRANSPORT_QUERY_NAME_SUCCESS)
        {
             LOG_LS_WARNING(MSGID_LSHUB_NO_SERVICE, 0, "%s: Failed Connecting to Service err_code: %ld, service_name: \"%s\", unique_name: \"%s\", %s, fd %d\n",
                            __func__, err_code, service_name, unique_name,
                            is_dynamic ? "dynamic" : "static", fd);
        }

        LOG_LS_DEBUG("%s: err_code: %ld, service_name: \"%s\", unique_name: \"%s\", %s, fd %d, groups: \"%s\", exe_path: \"%s\"\n",
                     __func__, err_code, service_name, unique_name,
                     is_dynamic ? "dynamic" : "static", fd, groups.c_str(), exe_path);

        // Set the connection fd on the message (-1 on error)
        _LSTransportMessageSetFd(reply_message, fd);

        if (!_LSTransportSendMessage(reply_message, client, NULL, lserror))
        {
            break;
        }

        _LSTransportMessageUnref(reply_message);
        return true;

    } while (false);

    if (reply_message) _LSTransportMessageUnref(reply_message);
    return false;
}

static bool
_LSHubSendQueryProxyNameReply(_ClientId *id, const char *origin_exe,
                              const char *origin_id, const char *origin_name,
                              const _LSTransportClient *origin_client, const _LSTransportMessage *message,
                              long err_code, const char *service_name, const char *unique_name,
                              bool is_dynamic, bool is_redirected, LSError *lserror) {
    LS_ASSERT(message != NULL);
    LS_ASSERT(service_name != NULL);

    bool ret = true;
    int socket_vector[2] = { -1, -1 };

    _LSTransportClient *client = _LSTransportMessageGetClient(message);
    LS_ASSERT(client);

    if (err_code == LS_TRANSPORT_QUERY_NAME_SUCCESS) {
        if (-1 == socketpair(AF_UNIX, SOCK_STREAM, 0, socket_vector)) {
            LOG_LS_ERROR(MSGID_LSHUB_SERVICE_CONNECT_ERROR, 3,
                         PMLOGKS("APP_ID", service_name),
                         PMLOGKFV("ERROR_CODE", "%d", errno),
                         PMLOGKS("ERROR", g_strerror(errno)),
                         "%s: Failed to create sockets for %s service \"%s\": "
                         "%s", __func__, is_dynamic ? "dynamic" : "static",
                         service_name, g_strerror(errno));

            // Replace original passed-in error code with this error
            err_code = LS_TRANSPORT_QUERY_NAME_SERVICE_NOT_AVAILABLE;
            ret = false;
        } else {
            const char *client_name = _LSTransportClientGetServiceName(client);
            const char *client_app_id =  _LSTransportClientGetApplicationId(client);

            // A unique_name is created here for proxy connection
            std::string unique_name_proxy = _CreateUniqueName();
            unique_name_proxy.append("_proxy");

            // Note: Allow only forwarding calls in proxy connection
            if (!_LSHubSendQueryProxyNameReplyMessage(id->client, client,
                                                      message->raw->header.is_public_bus,
                                                      err_code, client_name,
                                                      unique_name_proxy.c_str(),
                                                      client_app_id, client->is_dynamic, socket_vector[1],
                                                      _LSClientAllowInbound,
                                                      lserror, origin_exe, origin_id, origin_name, origin_client, false)) {
                err_code = LS_TRANSPORT_QUERY_NAME_SERVICE_NOT_AVAILABLE;
                ret = false;
            }
        }
    }

    if (!_LSHubSendQueryProxyNameReplyMessage(client, id ? id->client : nullptr,
                                              message->raw->header.is_public_bus,
                                              err_code, service_name, unique_name,
                                              id ? _LSTransportClientGetApplicationId(id->client) : nullptr,
                                              is_dynamic, socket_vector[0],
                                              _LSClientAllowOutbound,
                                              lserror, origin_exe, origin_id, origin_name, nullptr, true)) {
        ret = false;
    }

    return ret;
}

/**
 *******************************************************************************
 * @brief Send a reply to a "QueryName" message.
 *
 * @param  id            IN     details of the service which is being connected to
 * @param  message       IN     query name message to which we are replying
 * @param  err_code      IN     numeric error code (0 means success)
 * @param  service_name  IN     requested service name
 * @param  unique_name   IN     unique name of requested service
 * @param  is_dynamic    IN     true if the service is dynamic
 * @param  is_redirected IN     true if the client call the service by old service name
 * @param  lserror       OUT    set on error
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
// TODO: remove `is_redirected` parameter, after all services will migrate.
static bool
_LSHubSendQueryNameReply(_ClientId *id, const _LSTransportMessage *message, long err_code,
                         const char *service_name, const char *unique_name,
                         bool is_dynamic, bool is_redirected, LSError *lserror)
{
    LS_ASSERT(message != NULL);
    LS_ASSERT(service_name != NULL);

    bool ret = true;
    int socket_vector[2] = { -1, -1 };

    _LSTransportClient *client = _LSTransportMessageGetClient(message);
    LS_ASSERT(client);

    bool allow_reverse_calls = false;
    if (err_code == LS_TRANSPORT_QUERY_NAME_SUCCESS)
    {
        if (-1 == socketpair(AF_UNIX, SOCK_STREAM, 0, socket_vector))
        {
            LOG_LS_ERROR(MSGID_LSHUB_SERVICE_CONNECT_ERROR, 3,
                         PMLOGKS("APP_ID", service_name),
                         PMLOGKFV("ERROR_CODE", "%d", errno),
                         PMLOGKS("ERROR", g_strerror(errno)),
                         "%s: Failed to create sockets for %s service \"%s\": "
                         "%s", __func__, is_dynamic ? "dynamic" : "static",
                         service_name, g_strerror(errno));

            // Replace original passed-in error code with this error
            err_code = LS_TRANSPORT_QUERY_NAME_SERVICE_NOT_AVAILABLE;
            ret = false;
        }
        else
        {
            const char *client_name = _LSTransportClientGetServiceName(client);
            const char *client_app_id =  _LSTransportClientGetApplicationId(client);

            /* Due to the fact, we need deterministic behaviour for
             * migrated services, we allow reverse connections only in the name of
             * real service_name (com.webos.service.*). That's why we do not allow
             * reverse calls, if client connected to the service by alias (com.palm.*).
             * Also it should be either trusted service, or both services should have
             * appropriate permisions.
             * We don't use LSHubIsClientAllowedToQueryName to not produce warnings.
             */
            bool is_trusted_pair = false;
#if SECURITY_HACKS_ENABLED
            is_trusted_pair = _LSIsTrustedService(service_name) || _LSIsTrustedService(client_name);
#endif
            allow_reverse_calls = client_name && !is_redirected &&
                                  (is_trusted_pair ||
                                   (LSHubIsClientAllowedOutbound(id->client, client_name) &&
                                    LSHubIsClientAllowedInbound(id->client, client, client_name)));

            if (!_LSHubSendQueryNameReplyMessage(id->client, client,
                                  message->raw->header.is_public_bus,
                                  err_code, client_name,
                                  _LSTransportClientGetUniqueName(client),
                                  client_app_id, client->is_dynamic, socket_vector[1],
                                  allow_reverse_calls ? _LSClientAllowBoth : _LSClientAllowInbound,
                                  lserror))
            {
                err_code = LS_TRANSPORT_QUERY_NAME_SERVICE_NOT_AVAILABLE;
                ret = false;
            }
        }
    }

    if (!_LSHubSendQueryNameReplyMessage(client, id ? id->client : nullptr,
                                         message->raw->header.is_public_bus,
                                         err_code, service_name, unique_name,
                                         id ? _LSTransportClientGetApplicationId(id->client) : nullptr,
                                         is_dynamic, socket_vector[0],
                                         allow_reverse_calls ? _LSClientAllowBoth : _LSClientAllowOutbound,
                                         lserror))
    {
        ret = false;
    }

    return ret;
}

/**
 *******************************************************************************
 * @brief Send a query name reply to all clients waiting for this service.
 * The reply can be "success" or "failure".
 *
 * @param  id           IN      id of service
 * @param  success      IN      on true send success, otherwise send failure
 * @param  is_dynamic   IN      true if service is dynamic
 * @param  lserror      OUT     set on error
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
static bool
_LSHubSendServiceWaitListReply(_ClientId *id, bool success, bool is_dynamic, LSError *lserror) {
    long ret_code;

    if (success) {
        ret_code = LS_TRANSPORT_QUERY_NAME_SUCCESS;
    } else {
        ret_code = LS_TRANSPORT_QUERY_NAME_SERVICE_NOT_AVAILABLE;
    }

    /*
     * Multiple clients may be waiting for this service, so we iterate over
     * all of those waiting and send replies
     */

    GSList *iter = waiting_for_service;
    while (iter) {
        _LSTransportMessage *query_message = reinterpret_cast<_LSTransportMessage*>(iter->data);

        const char *requested_service = NULL;
        const char *origin_name = NULL;
        const char *origin_id = NULL;
        const char *origin_exe = NULL;

        _LSTransportMessageType message_type = _LSTransportMessageGetType(query_message);

        if (_LSTransportMessageTypeQueryName == message_type) {
            requested_service = _LSTransportMessageTypeQueryNameGetQueryName(query_message);
        } else {
            requested_service = _LSTransportMessageTypeQueryProxyNameGetQueryName(query_message);
            origin_name = _LSTransportMessageTypeQueryProxyNameGetOriginName(query_message);
            origin_id = _LSTransportMessageTypeQueryProxyNameGetOriginId(query_message);
            origin_exe = _LSTransportMessageTypeQueryProxyNameGetOriginExePath(query_message);
        }
        LS_ASSERT(requested_service != NULL);
        std::string destination_service;
        if (strcmp(requested_service, id->service_name) == 0) {
            destination_service = requested_service;
        } else {
            for (const auto& name : GetServiceRedirectionVariants(requested_service)) {
                if (name.compare(id->service_name) == 0) {
                    destination_service = name;
                    break;
                }
            }
        }

        if (!destination_service.empty()) {
            /* we found a client waiting for this service */

#ifdef DEBUG
            LOG_LS_DEBUG("Sending QueryProxyNameReply for service: \"%s\" to client: \"%s\" (\"%s\")\n",
                         id->service_name, query_message->client->service_name, query_message->client->unique_name);
#endif

            /* In case we had multiple permissions for the service name, we should check
             * permissions again. This time according to the service exepath */
            if (_LSTransportMessageTypeQueryName == message_type) {
                if (!LSHubIsClientAllowedToQueryName(query_message->client, id->client,
                                                     destination_service.c_str())) {
                    ret_code = LS_TRANSPORT_QUERY_NAME_PERMISSION_DENIED;
                }
            } else {
                if (!LSHubIsAllowedToQueryProxyName(origin_exe,
                                                    origin_id,
                                                    origin_name,
                                                    NULL,
                                                    id->client,
                                                    destination_service.c_str())) {
                    ret_code = LS_TRANSPORT_QUERY_NAME_PERMISSION_DENIED;
                }
            }

            if (_LSTransportMessageTypeQueryName == message_type) {
                if (!_LSHubSendQueryNameReply(id, query_message, ret_code, requested_service,
                                            id->local.name, is_dynamic,
                                            (destination_service.compare(requested_service) == 0), lserror)) {
                    LOG_LSERROR(MSGID_LSHUB_SENDMSG_ERROR, lserror);
                    LSErrorFree(lserror);
                }
            } else {
                if (!_LSHubSendQueryProxyNameReply(id,
                                                   origin_exe,
                                                   origin_id,
                                                   origin_name,
                                                   NULL,
                                                   query_message,
                                                   ret_code,
                                                   requested_service,
                                                   id->local.name,
                                                   is_dynamic,
                                                   (destination_service.compare(requested_service) == 0),
                                                   lserror)) {
                    LOG_LSERROR(MSGID_LSHUB_SENDMSG_ERROR, lserror);
                    LSErrorFree(lserror);
                }
            }

            /* remove the timeout if there is one */
            _LSHubRemoveMessageTimeout(query_message);

            /* ref associated with waiting_for_service list */
            _LSTransportMessageUnref(query_message);

            GSList *remove_node = iter;
            iter = g_slist_next(iter);

            waiting_for_service = g_slist_delete_link(waiting_for_service, remove_node);
        } else {
            iter = g_slist_next(iter);
        }
    }

    return true;
}

void
DumpHashItem(gpointer key, gpointer value, gpointer user_data)
{
    printf("key: \"%s\", value: %p\n", (char*)key, value);
}

void
DumpHashTable(GHashTable *table)
{
    LS_ASSERT(table != NULL);

    g_hash_table_foreach(table, DumpHashItem, NULL);
    printf("\n");
    fflush(stdout);
}

/**
 *******************************************************************************
 * @brief Process a "NodeUp" message.
 *
 * @param  message  IN      node up message to process
 *******************************************************************************
 */
static void
_LSHubHandleNodeUp(_LSTransportMessage *message)
{
    LOG_LS_DEBUG("%s\n", __func__);

    LSError lserror;
    LSErrorInit(&lserror);

#ifdef DEBUG
    //printf("%s: pending hash table:\n", __func__);
    DumpHashTable(pending);
    //printf("%s: available_services hash table:\n", __func__);
    DumpHashTable(available_services);
#endif

    /* the node is up, so move it to the list of available services */
    _LSTransportClient *client = _LSTransportMessageGetClient(message);

    const char *exe_path = NULL;

    /* Use exe_path in client credentials to look up role file and allowed service names */
    const _LSTransportCred *cred = _LSTransportClientGetCred(client);

    pid_t pid = _LSTransportCredGetPid(cred);

    /*
     * FIXME: this won't work if we want to mux multiple services in the same
     * process through the same connection
     */
    _ClientId *id = static_cast<_ClientId *>(g_hash_table_lookup(connected_clients.by_fd, GINT_TO_POINTER(client->channel.fd)));

    if (!id)
    {
        LOG_LS_ERROR(MSGID_LSHUB_NO_CLIENT, 0, "Could not find client using fd");
        return;
    }


    bool is_public_bus = message->raw->header.is_public_bus;
    if (!id->service_name)
    {
        /* A non-service came up. For legacy compatibility with subscriptions
         * we send a service status message, using the unique name as the
         * service name */
        auto allowed_name = mk_ptr(g_strdup_printf("\"%s\"", id->local.name), g_free);

        _LSHubSendServiceUpSignal(id->local.name, id->local.name, pid,
                                  allowed_name.get(), is_public_bus);
        return;
    }

    LS_ASSERT(id->service_name != NULL);

    /* stealing doesn't call key and value destroy functions */
    bool is_new_node = g_hash_table_steal(pending, id->service_name);

#ifndef WEBOS_MASS_PRODUCTION
    if (!is_new_node)
    {
        // NodeUp is sent for every LSRegister(). The first one removes the client id
        // from the hash table pending. The second may appear in legacy services
        // which used to register on public/private hubs separately.
        LOG_LS_WARNING(MSGID_LS_OLD_PALM_SERVICE_DETECTED, 1,
                PMLOGKS("APP_ID", id->service_name),
                "Old Palm services are deprecated. You should not LSRegister twice.");
    }
#endif

    /* if it's a dynamic service, update its state to running */
    _Service *dynamic = _DynamicServiceStateMapLookup(id->service_name);
    if (dynamic)
    {
        _DynamicServiceState state = _DynamicServiceGetState(dynamic);

        switch (state)
        {
        case _DynamicServiceStateSpawned:
            /* launched dynamically */
            _DynamicServiceSetState(dynamic, _DynamicServiceStateRunningDynamic);
            break;
        case _DynamicServiceStateStopped:
            /* launched manually */
            _DynamicServiceSetState(dynamic, _DynamicServiceStateRunning);
            break;
        case _DynamicServiceStateRunning:
        case _DynamicServiceStateRunningDynamic:
            break;
        default:
            LOG_LS_ERROR(MSGID_LSHUB_INVALID_STATE, 0, "Unexpected dynamic service state: %d", state);
        }
    }

    /* move into the available hash */
    if (is_new_node)
        g_hash_table_replace(available_services, id->service_name, id);

    /* Go through list of clients waiting for a service to come up
     * and send them a message letting them know it is now up */
    if (!_LSHubSendServiceWaitListReply(id, true, dynamic ? dynamic->is_dynamic : false, &lserror))
    {
        LOG_LSERROR(MSGID_LSHUB_SENDMSG_ERROR, &lserror);
        LSErrorFree(&lserror);
    }

    if (cred)
        exe_path = _LSTransportCredGetExePath(cred);

    std::string allowed_names;
    if (exe_path)
    {
        const LSHubRole *role = SecurityData::CurrentSecurityData().roles.Lookup(exe_path);
        allowed_names = LSHubRoleAllowedNamesDump(role);
    }

    _LSHubSendServiceUpSignal(id->service_name, id->local.name, pid, allowed_names.c_str(),
                              is_public_bus);
    for (const auto& name : GetServiceRedirectionVariants(id->service_name))
    {
        /* Let registered clients know that this service is up */
        if (!g_hash_table_lookup(available_services, name.c_str()))
            _LSHubSendServiceUpSignal(name.c_str(), id->local.name, pid, allowed_names.c_str(),
                                      is_public_bus);
    }

    if (g_conf_log_service_status)
    {
        LOG_LS_DEBUG("SERVICE: ServiceUp (name: \"%s\", dynamic: %s, pid: " LS_PID_PRINTF_FORMAT ", "
                  "exe: \"%s\", cmdline: \"%s\")",
                   id->service_name, dynamic ? "true" : "false",
                   LS_PID_PRINTF_CAST(pid),
                   exe_path,
                   _LSTransportCredGetCmdLine(cred));
    }

#ifdef DEBUG
    //printf("%s: pending hash table:\n", __func__);
    DumpHashTable(pending);
    //printf("%s: available_services hash table:\n", __func__);
    DumpHashTable(available_services);

    //printf("service is up: \"%s\"\n", id->service_name);
#endif
}

/**
 *******************************************************************************
 * @brief Send a failure response to a query name message that timed out.
 *
 * @param  message  IN  query name message that timed out
 *
 * @retval FALSE always so the timer does not fire again
 *******************************************************************************
 */
gboolean
_LSHubHandleQueryNameTimeout(_LSTransportMessage *message)
{
    LSError lserror;
    LSErrorInit(&lserror);

    /* remove the message from the waiting list */
    waiting_for_service = g_slist_remove(waiting_for_service, message);

    const char *requested_service = NULL;

    _LSTransportMessageType message_type = _LSTransportMessageGetType(message);

    if (_LSTransportMessageTypeQueryName == message_type) {
        requested_service = _LSTransportMessageTypeQueryNameGetQueryName(message);
    } else {
        requested_service = _LSTransportMessageTypeQueryProxyNameGetQueryName(message);
    }

    if (!requested_service) {
        LOG_LS_ERROR(MSGID_LSHUB_NO_SERVICE, 0, "Failed to get service name for timeout message");
    } else { /* the service didn't come up in time, so send a failure message */
        if (_LSTransportMessageTypeQueryName == message_type) {
            if (!_LSHubSendQueryNameReply(NULL, message, LS_TRANSPORT_QUERY_NAME_TIMEOUT, requested_service,
                                      NULL, false, false, &lserror)) {
                LOG_LSERROR(MSGID_LSHUB_SENDMSG_ERROR, &lserror);
                LSErrorFree(&lserror);
            }
        } else if (_LSTransportMessageTypeQueryProxyName == message_type) {
            const char *origin_name = _LSTransportMessageTypeQueryProxyNameGetOriginName(message);
            const char *origin_id = _LSTransportMessageTypeQueryProxyNameGetOriginId(message);
            const char *origin_exe = _LSTransportMessageTypeQueryProxyNameGetOriginExePath(message);

            if (!_LSHubSendQueryProxyNameReply(NULL, origin_exe, origin_id,
                                           origin_name, NULL,
                                           message,
                                           LS_TRANSPORT_QUERY_NAME_TIMEOUT,
                                           requested_service,
                                           NULL,
                                           false, false,
                                           &lserror)) {
                LOG_LSERROR(MSGID_LSHUB_SENDMSG_ERROR, &lserror);
                LSErrorFree(&lserror);
            }
        }
    }

    /* refcount associated with the list */
    _LSTransportMessageUnref(message);
    _LSHubRemoveMessageTimeout(message);

    return FALSE;   /* don't fire the timer again */
}

/**
 *******************************************************************************
 * @brief Add a timeout to message.
 *
 * @param  message      IN  message
 * @param  timeout_ms   IN  timeout in milliseconds
 * @param  callback     IN  callback to call after timeout
 *******************************************************************************
 */
static void
_LSHubAddMessageTimeout(_LSTransportMessage *message, int timeout_ms, GSourceFunc callback)
{
    _LSTransportMessageRef(message);

    GTimerSource *source = g_timer_source_new (timeout_ms, MESSAGE_TIMEOUT_GRANULARITY_MS);

    g_source_set_callback ((GSource*)source, callback, message, NULL);
    guint timeout_id = g_source_attach ((GSource*)source, NULL);

    _LSTransportMessageSetTimeoutId(message, timeout_id);
}

/**
 *******************************************************************************
 * @brief Remove a timeout from a message.
 *
 * @param  message  IN  query name message
 *******************************************************************************
 */
static void
_LSHubRemoveMessageTimeout(_LSTransportMessage *message)
{
    /* remove timeout source from mainloop */
    GSource *timeout_source = g_main_context_find_source_by_id(NULL, _LSTransportMessageGetTimeoutId(message));

    if (timeout_source)
    {
        g_source_destroy(timeout_source);
        g_source_unref(timeout_source);
    }

    /* clear timeout id */
    _LSTransportMessageSetTimeoutId(message, 0);

    _LSTransportMessageUnref(message);
}

/**
 *******************************************************************************
 * @brief Add a timeout to a "QueryName" message.
 *
 * @param  message  IN  message
 *******************************************************************************
 */
static void
_LSHubAddQueryNameMessageTimeout(_LSTransportMessage *message)
{
    _LSTransportMessageRef(message);
    waiting_for_service = g_slist_prepend(waiting_for_service, message);
    _LSHubAddMessageTimeout(message, g_conf_query_name_timeout_ms, (GSourceFunc)_LSHubHandleQueryNameTimeout);
}

/**
 *******************************************************************************
 * @brief Cleanup outgoing queue from messages with invalid (closed) sockets.
 *
 * @param queue outgoing queue
 *******************************************************************************
 */
static void
_LSHubCleanupOutgoingQueue(GQueue *queue)
{
    int len = g_queue_get_length(queue);
    while (--len >= 0)
    {
        _LSTransportMessage *message = (_LSTransportMessage *) g_queue_pop_head(queue);
        if ((_LSTransportMessageGetType(message) == _LSTransportMessageTypeQueryNameReply) ||
            (_LSTransportMessageGetType(message) == _LSTransportMessageTypeQueryProxyNameReply))
        {
            int fd = _LSTransportMessageGetFd(message);

            // Lets try to write into the socket. If socket is valid, function should
            // return 0, else -1 and errno will be set to EPIPE (in case other
            // side has closed the socket).
            if (write(fd, NULL, 0) == -1 && EPIPE == errno)
            {
                _LSTransportMessageFree(message);
                continue;
            }
        }
        g_queue_push_tail(queue, message);
    }
}

static void
_LSHubHandleQueryProxyName(_LSTransportMessage *message) {
    LOG_LS_DEBUG("%s\n", __func__);

    LSError lserror;
    LSErrorInit(&lserror);

#ifdef DEBUG
    //printf("%s: available_services hash table:\n", __func__);
    DumpHashTable(available_services);
#endif

    const char *requested_service_name = _LSTransportMessageTypeQueryProxyNameGetQueryName(message);
    LS_ASSERT(requested_service_name != NULL);

    /* If the message originated from a application service, we will get a non-NULL appId
     * from this call. */
    const char *app_id = _LSTransportMessageTypeQueryProxyNameGetAppId(message);

    // Extract invoker details
    const char *origin_name = _LSTransportMessageTypeQueryProxyNameGetOriginName(message);
    const char *origin_id = _LSTransportMessageTypeQueryProxyNameGetOriginId(message);
    const char *origin_exe = _LSTransportMessageTypeQueryProxyNameGetOriginExePath(message);
    if (!origin_name)
    {
        LOG_LS_ERROR(MSGID_LS_NOT_AN_ERROR,0,"%s - Proxy message origin_name is NULL. Not proceeding further.",__func__);
        return;
    }
    _ClientId *origin_client_id = static_cast<_ClientId *>(g_hash_table_lookup(available_services, origin_name));
    _LSTransportClient *origin_client = origin_client_id ? origin_client_id->client : nullptr;

    if (!((LSHubClientGetPrivileged(_LSTransportMessageGetClient(message)) ||
        LSHubClientGetProxy(_LSTransportMessageGetClient(message))) &&
        (LSHubIsClientProxyAgent(_LSTransportMessageGetClient(message))))) {
        if (!_LSHubSendQueryProxyNameReply(NULL, origin_exe, origin_id,
                                           origin_name, origin_client,
                                           message,
                                           LS_TRANSPORT_QUERY_NAME_PROXY_AUTH_ERROR,
                                           requested_service_name,
                                           NULL,
                                           false, false,
                                           &lserror)) {
            LOG_LSERROR(MSGID_LSHUB_SENDMSG_ERROR, &lserror);
            LSErrorFree(&lserror);
        }
        return;
    }

    /* Check to see if the service exists */
    ServiceMap &smap = SecurityData::CurrentSecurityData().services;
    _Service *service = smap.Lookup(requested_service_name);
    std::string destination_service_name = requested_service_name;

    if (!service) {
        for (const auto& name : GetServiceRedirectionVariants(requested_service_name)) {
            service = smap.Lookup(name);
            if (service) {
                destination_service_name = name;
                break;
            }
        }
    }

    if (!service) {
        // Requested service as well as possible migration candidate for it haven't been found.
        G_GNUC_UNUSED const _LSTransportCred *cred = _LSTransportClientGetCred(_LSTransportMessageGetClient(message));
        LOG_LS_ERROR(MSGID_LSHUB_SERVICE_NOT_LISTED, 4,
                     PMLOGKS("SERVICE_NAME", requested_service_name),
                     PMLOGKS("EXE", _LSTransportCredGetExePath(cred)),
                     PMLOGKS("APP_ID", app_id),
                     PMLOGKFV("PID", LS_PID_PRINTF_FORMAT, LS_PID_PRINTF_CAST(_LSTransportCredGetPid(cred))),
                     "Service not listed in service files (cmdline: %s)",
                     _LSTransportCredGetCmdLine(cred));

        /* The service is not in a service file, so it doesn't exist
         * in the system and we should return error */
        if (!_LSHubSendQueryProxyNameReply(NULL, origin_exe, origin_id,
                                           origin_name, origin_client,
                                           message,
                                           LS_TRANSPORT_QUERY_NAME_SERVICE_NOT_EXIST,
                                           requested_service_name,
                                           NULL,
                                           false, false,
                                           &lserror)) {
            LOG_LSERROR(MSGID_LSHUB_SENDMSG_ERROR, &lserror);
            LSErrorFree(&lserror);
        }
        return;
    }

    // Continue with the substituted name.
    bool service_is_dynamic = service->is_dynamic;

    _ClientId *id = static_cast<_ClientId *>(g_hash_table_lookup(available_services, destination_service_name.c_str()));
    _LSTransportClient *dest_client = id ? id->client : nullptr;

    // Sometimes if service is hanging out or stopped, we may have invalid
    // opened file descriptors in an outgoing queue. Socket buffer can contain
    // about 30 messages. So if we have any messages in an outgoing queue,
    // socket buffer is full, and service is freezing for a long period of time.
    // To increase chances for new clients to connect, we may cleanup an outgoing
    // queue from messages with invalid socket fds.
    if (dest_client &&
        dest_client->outgoing->queue &&
        !g_queue_is_empty(dest_client->outgoing->queue)) {
        _LSHubCleanupOutgoingQueue(dest_client->outgoing->queue);
    }

    // We know the service exists, so now we check to see if we have
    // appropriate permissions to talk to the service.
    // If we're looking for a service substitute (com.palm -> com.webos.service),
    // avoid checking inbound/outbound lists, because they're likely to be broken.
    // API will be restricted with ACG only.
    if ((requested_service_name == destination_service_name) &&
        !LSHubIsAllowedToQueryProxyName(origin_exe,
                                        origin_id,
                                        origin_name,
                                        origin_client,
                                        dest_client,
                                        requested_service_name)) {
        if (!_LSHubSendQueryProxyNameReply(id,
                                           origin_exe,
                                           origin_id,
                                           origin_name,
                                           origin_client,
                                           message,
                                           LS_TRANSPORT_QUERY_NAME_PERMISSION_DENIED,
                                           requested_service_name,
                                           NULL,
                                           false, false,
                                           &lserror)) {
            LOG_LSERROR(MSGID_LSHUB_SENDMSG_ERROR, &lserror);
            LSErrorFree(&lserror);
        }
        return;
    }

    if (!id) {
        id = static_cast<_ClientId *>(g_hash_table_lookup(pending, destination_service_name.c_str()));

        if (!id) {
            /* Not available or pending. We know that the service *should*
             * exist because we checked the service files earlier and
             * found it. */
            if (service_is_dynamic) {
                bool launched = _DynamicServiceFindandLaunch(destination_service_name.c_str(),
                                                             _LSTransportMessageGetClient(message),
                                                             app_id,
                                                             &lserror);

                if (!launched) {
                    LOG_LSERROR(MSGID_LSHUB_SERVICE_LAUNCH_ERR, &lserror);
                    LSErrorFree(&lserror);

                    /* If we failed to launch, return error */
                    if (!_LSHubSendQueryProxyNameReply(NULL, origin_exe, origin_id,
                                                       origin_name, origin_client,
                                                       message,
                                                       LS_TRANSPORT_QUERY_NAME_SERVICE_NOT_AVAILABLE,
                                                       requested_service_name,
                                                       NULL,
                                                       false, false,
                                                       &lserror)) {
                        LOG_LSERROR(MSGID_LSHUB_SENDMSG_ERROR, &lserror);
                        LSErrorFree(&lserror);
                    }
                    return;
                }
            }
            /* !service->is_dynamic */
        }

        /*
         * It's either pending, we just dynamically launched the process that
         * will provide the service, or it's a static service that currently
         * isn't up.
         *
         * In any of these cases, save the client info so we can send a
         * response when it actually comes up
         */
        _LSHubAddQueryNameMessageTimeout(message);

        return;
    }

    const char *unique_name = id->local.name;

    LS_ASSERT(unique_name != NULL);

    /* found name; create response and send it off */
    if (!_LSHubSendQueryProxyNameReply(id, origin_exe, origin_id,
                                       origin_name, origin_client,
                                       message,
                                       LS_TRANSPORT_QUERY_NAME_SUCCESS,
                                       requested_service_name,
                                       unique_name,
                                       service_is_dynamic,
                                       requested_service_name != destination_service_name,
                                       &lserror)) {
        LOG_LSERROR(MSGID_LSHUB_SENDMSG_ERROR, &lserror);
        LSErrorFree(&lserror);

        if (service_is_dynamic && ECONNREFUSED == lserror.error_code) {
            /*
                We caught the dynamic service going down. Retry connecting and sending the reply later when the service comes back up.
            */
            service->respawn_on_exit = true;

            _LSHubAddQueryNameMessageTimeout(message);
        }
    }
}

/**
 *******************************************************************************
 * @brief Process a "QueryName" message.
 *
 * @param  message  IN  query name message
 *******************************************************************************
 */
static void
_LSHubHandleQueryName(_LSTransportMessage *message)
{
    LOG_LS_DEBUG("%s\n", __func__);

    LSError lserror;
    LSErrorInit(&lserror);

#ifdef DEBUG
    //printf("%s: available_services hash table:\n", __func__);
    DumpHashTable(available_services);
#endif

    const char *requested_service_name = _LSTransportMessageTypeQueryNameGetQueryName(message);
    LS_ASSERT(requested_service_name != NULL);

    /* If the message originated from a application service, we will get a non-NULL appId
     * from this call. */
    const char *app_id = _LSTransportMessageTypeQueryNameGetAppId(message);

    /* Check to see if the service exists */
    ServiceMap &smap = SecurityData::CurrentSecurityData().services;
    _Service *service = smap.Lookup(requested_service_name);
    std::string destination_service_name = requested_service_name;

    if (!service)
    {
        for (const auto& name : GetServiceRedirectionVariants(requested_service_name))
        {
            service = smap.Lookup(name);
            if (service)
            {
                destination_service_name = name;
                break;
            }
        }
    }

    if (!service)
    {
        // Requested service as well as possible migration candidate for it haven't been found.
        G_GNUC_UNUSED const _LSTransportCred *cred = _LSTransportClientGetCred(_LSTransportMessageGetClient(message));
        LOG_LS_ERROR(MSGID_LSHUB_SERVICE_NOT_LISTED, 4,
                     PMLOGKS("SERVICE_NAME", requested_service_name),
                     PMLOGKS("EXE", _LSTransportCredGetExePath(cred)),
                     PMLOGKS("APP_ID", app_id),
                     PMLOGKFV("PID", LS_PID_PRINTF_FORMAT, LS_PID_PRINTF_CAST(_LSTransportCredGetPid(cred))),
                     "Service not listed in service files (cmdline: %s)",
                     _LSTransportCredGetCmdLine(cred));

        /* The service is not in a service file, so it doesn't exist
         * in the system and we should return error */
        if (!_LSHubSendQueryNameReply(NULL,
                                      message,
                                      LS_TRANSPORT_QUERY_NAME_SERVICE_NOT_EXIST,
                                      requested_service_name,
                                      NULL,
                                      false, false,
                                      &lserror))
        {
            LOG_LSERROR(MSGID_LSHUB_SENDMSG_ERROR, &lserror);
            LSErrorFree(&lserror);
        }
        return;
    }

    // Continue with the substituted name.
    bool service_is_dynamic = service->is_dynamic;

    _ClientId *id = static_cast<_ClientId *>(g_hash_table_lookup(available_services, destination_service_name.c_str()));
    _LSTransportClient *dest_client = id ? id->client : nullptr;

    // Sometimes if service is hanging out or stopped, we may have invalid
    // opened file descriptors in an outgoing queue. Socket buffer can contain
    // about 30 messages. So if we have any messages in an outgoing queue,
    // socket buffer is full, and service is freezing for a long period of time.
    // To increase chances for new clients to connect, we may cleanup an outgoing
    // queue from messages with invalid socket fds.
    if (dest_client &&
        dest_client->outgoing->queue &&
        !g_queue_is_empty(dest_client->outgoing->queue))
    {
        _LSHubCleanupOutgoingQueue(dest_client->outgoing->queue);
    }

    // We know the service exists, so now we check to see if we have
    // appropriate permissions to talk to the service.
    // If we're looking for a service substitute (com.palm -> com.webos.service),
    // avoid checking inbound/outbound lists, because they're likely to be broken.
    // API will be restricted with ACG only.
    if ((requested_service_name == destination_service_name) &&
        !LSHubIsClientAllowedToQueryName(_LSTransportMessageGetClient(message),
                                         dest_client,
                                         requested_service_name))
    {
        if (!_LSHubSendQueryNameReply(id,
                                      message,
                                      LS_TRANSPORT_QUERY_NAME_PERMISSION_DENIED,
                                      requested_service_name,
                                      NULL,
                                      false, false,
                                      &lserror))
        {
            LOG_LSERROR(MSGID_LSHUB_SENDMSG_ERROR, &lserror);
            LSErrorFree(&lserror);
        }
        return;
    }

    if (!id)
    {
        id = static_cast<_ClientId *>(g_hash_table_lookup(pending, destination_service_name.c_str()));

        if (!id)
        {
            /* Not available or pending. We know that the service *should*
             * exist because we checked the service files earlier and
             * found it. */
            if (service_is_dynamic)
            {
                bool launched = _DynamicServiceFindandLaunch(destination_service_name.c_str(),
                                                             _LSTransportMessageGetClient(message),
                                                             app_id,
                                                             &lserror);

                if (!launched)
                {
                    LOG_LSERROR(MSGID_LSHUB_SERVICE_LAUNCH_ERR, &lserror);
                    LSErrorFree(&lserror);

                    /* If we failed to launch, return error */
                    if (!_LSHubSendQueryNameReply(NULL,
                                                  message,
                                                  LS_TRANSPORT_QUERY_NAME_SERVICE_NOT_AVAILABLE,
                                                  requested_service_name,
                                                  NULL,
                                                  false, false,
                                                  &lserror))
                    {
                        LOG_LSERROR(MSGID_LSHUB_SENDMSG_ERROR, &lserror);
                        LSErrorFree(&lserror);
                    }
                    return;
                }
            }
            /* !service->is_dynamic */
        }

        /*
         * It's either pending, we just dynamically launched the process that
         * will provide the service, or it's a static service that currently
         * isn't up.
         *
         * In any of these cases, save the client info so we can send a
         * response when it actually comes up
         */
        _LSHubAddQueryNameMessageTimeout(message);

        return;
    }

    const char *unique_name = id->local.name;

    LS_ASSERT(unique_name != NULL);

    /* found name; create response and send it off */
    if (!_LSHubSendQueryNameReply(id,
                                  message,
                                  LS_TRANSPORT_QUERY_NAME_SUCCESS,
                                  requested_service_name,
                                  unique_name,
                                  service_is_dynamic,
                                  requested_service_name != destination_service_name,
                                  &lserror))
    {
        LOG_LSERROR(MSGID_LSHUB_SENDMSG_ERROR, &lserror);
        LSErrorFree(&lserror);

        if (service_is_dynamic && ECONNREFUSED == lserror.error_code)
        {
            /*
                We caught the dynamic service going down. Retry connecting and sending the reply later when the service comes back up.
            */
            service->respawn_on_exit = true;

            _LSHubAddQueryNameMessageTimeout(message);
        }
    }
}

/**
 *******************************************************************************
 * @brief Send a signal message to a client.
 *
 * @param  client   IN  client to which signal should be sent
 * @param  dummy    IN  unused
 * @param  message  IN  message to forward as the signal
 *******************************************************************************
 */
static void
_LSHubSendSignal(_LSTransportClient *client, void *dummy, _LSTransportMessage *message)
{
    LSError lserror;
    LSErrorInit(&lserror);
    LSMessageToken token;

    /* Need to make a copy of the message, since this function gets called
     * multiple times with the same message.
     *
     * TODO: It would be nice to avoid the message copies for performance,
     * but we need to have independent message transmit counts since the
     * message is sent to different clients
     */

    _LSTransportMessage *msg_copy = _LSTransportMessageCopyNewRef(message);

    if (!_LSTransportSendMessage(msg_copy, client, &token, &lserror))
    {
        LOG_LSERROR(MSGID_LSHUB_SENDMSG_ERROR, &lserror);
        LSErrorFree(&lserror);
    }

    _LSTransportMessageUnref(msg_copy);
}

/**
 *******************************************************************************
 * @brief Remove a @ref LSTransportClient from the @ref _LSTransportClientMap
 * regardless of the ref count in the @ref _LSTransportClientMap.
 *
 * @param  key          IN  unused
 * @param  value        IN  _LSTransportClientMap
 * @param  user_data    IN  @ref LSTransportClient
 *
 * @retval  TRUE if the _LSTransportClientMap is empty and should be
 * free'd
 * @retval  FALSE otherwise
 *******************************************************************************
 */
static gboolean
_LSTransportClientMapRemoveCallback(gpointer key, gpointer value, gpointer user_data)
{
    _LSTransportClient *client = (_LSTransportClient*)user_data;
    _LSTransportClientMap *client_map = (_LSTransportClientMap*)value;

    /* remove regardless of ref_count because the client is going down */
    _LSTransportClientMapRemove(client_map, client);

    if (_LSTransportClientMapIsEmpty(client_map))
    {
        return TRUE;    /* client map is free'd by destroy func */
    }
    return FALSE;
}

/**
 *******************************************************************************
 * @brief Remove all references to the client in the signal map (all the
 * signals that it registered for).
 *
 * @param  client   client
 *
 * @retval true always
 *******************************************************************************
 */
static bool
_LSHubRemoveClientSignals(_LSTransportClient *client)
{
    /*
     * FIXME: this is quite inefficient: O(num_registered_signals * num_clients)
     */
    g_hash_table_foreach_remove(signal_map->category_map, _LSTransportClientMapRemoveCallback, client);
    g_hash_table_foreach_remove(signal_map->method_map, _LSTransportClientMapRemoveCallback, client);
    return true;
}

/**
 *******************************************************************************
 * @brief Remove a client's registration for the given signal.
 *
 * @param  map      IN  signal's "method_map" or "category_map"
 * @param  path     IN  signal to unregister for
 * @param  client   In  client
 *
 * @retval  true if signal registration was removed
 * @retval  false otherwise
 *******************************************************************************
 */
static bool
_LSHubRemoveSignal(GHashTable *map, const char *path, _LSTransportClient *client)
{
    bool ret = false;

    _LSTransportClientMap *client_map = static_cast<_LSTransportClientMap *>(g_hash_table_lookup(map, path));

    if (client_map)
    {
        ret = _LSTransportClientMapUnrefClient(client_map, client);

        if (_LSTransportClientMapIsEmpty(client_map))
        {
            /* if client_map is empty, we should remove "path" from
             * the hash table */
            bool remove_ret = g_hash_table_remove(map, path);
            LS_ASSERT(remove_ret == true);

            /* client_map is free'd by destroy func when remove is called */
        }
    }

    return ret;
}

/**
 *******************************************************************************
 * @brief Process a signal unregistration message.
 *
 * @param  message  IN  signal unregister message
 *******************************************************************************
 */
static void
_LSHubHandleSignalUnregister(_LSTransportMessage *message)
{
    const char *category = _LSTransportMessageGetCategory(message);
    const char *method = _LSTransportMessageGetMethod(message);
    _LSTransportClient *client = _LSTransportMessageGetClient(message);

    LOG_LS_DEBUG("%s: category: \"%s\", method: \"%s\", client: %p\n", __func__, category, method, client);

    LS_ASSERT(category != NULL);

    /* if method, remove from category/method hash */
    if (method[0] != '\0')
    {
        char *full_path = g_strdup_printf("%s/%s", category, method);

        if (!_LSHubRemoveSignal(signal_map->method_map, full_path, client))
        {
            G_GNUC_UNUSED const _LSTransportCred *cred = _LSTransportClientGetCred(client);
            LOG_LS_ERROR(MSGID_LSHUB_SIGNAL_ERR, 3,
                         PMLOGKS("PATH", full_path),
                         PMLOGKS("EXE", _LSTransportCredGetExePath(cred)),
                         PMLOGKFV("PID", LS_PID_PRINTF_FORMAT, LS_PID_PRINTF_CAST(_LSTransportCredGetPid(cred))),
                         "Unable to remove signal (cmdline: %s)",
                         _LSTransportCredGetCmdLine(cred));
        }
        g_free(full_path);
    }
    else
    {
        /* remove from category hash */
        if (!_LSHubRemoveSignal(signal_map->category_map, category, client))
        {
            G_GNUC_UNUSED const _LSTransportCred *cred = _LSTransportClientGetCred(client);
            LOG_LS_ERROR(MSGID_LSHUB_SIGNAL_ERR, 3,
                         PMLOGKS("CATEGORY", category),
                         PMLOGKS("EXE", _LSTransportCredGetExePath(cred)),
                         PMLOGKFV("PID", LS_PID_PRINTF_FORMAT, LS_PID_PRINTF_CAST(_LSTransportCredGetPid(cred))),
                         "Unable to remove signal (cmdline: %s)",
                         _LSTransportCredGetCmdLine(cred));
        }
    }

    /* TODO: remove from reverse lookup */
}

/**
 *******************************************************************************
 * @brief Add a client's registration for a given signal.
 *
 * @param  map      IN  signal's "method_map" or "category_map"
 * @param  path     IN  signal to register for
 * @param  client   In  client
 *
 * @retval  true if signal registration was added
 * @retval  false otherwise
 *******************************************************************************
 */
static bool
_LSHubAddSignal(GHashTable *map, const char *path, _LSTransportClient *client)
{
    LS_ASSERT(map != NULL);
    LS_ASSERT(path != NULL);
    LS_ASSERT(client != NULL);

    _LSTransportClientMap *client_map = static_cast<_LSTransportClientMap *>(g_hash_table_lookup(map, path));

    if (!client_map)
    {
        client_map = _LSTransportClientMapNew();

        char *path_copy = g_strdup(path);

        g_hash_table_replace(map, (gpointer)path_copy, client_map);
    }

    _LSTransportClientMapAddRefClient(client_map, client);

    return true;
}

/**
 *******************************************************************************
 * @brief Utility routine used by _LSHubSignalRegisterAllServices, for iteration.
 *
 * @param  key    IN  service name
 * @param  value  IN  _ClientId pointer
 * @param  user_data IN  GString * where results will be accumulated
 *******************************************************************************
 */
static void
_LSHubSignalRegisterAllServicesItem(gpointer key, gpointer value, gpointer user_data)
{
    GString * str = (GString*)user_data;
    _ClientId * client = (_ClientId*)value;

    const char *exe_path = NULL;

    /* Use exe_path in client credentials to look up role file and allowed service names */
    const _LSTransportCred *cred = NULL;

    LS_ASSERT(client);
    if (client->client)
        cred = _LSTransportClientGetCred(client->client);

    pid_t pid = 0;

    if (cred)
        pid = _LSTransportCredGetPid(cred);

    if (cred)
        exe_path = _LSTransportCredGetExePath(cred);

    std::string allowed_names;
    if (exe_path)
    {
        auto role = SecurityData::CurrentSecurityData().roles.Lookup(exe_path);
        allowed_names = LSHubRoleAllowedNamesDump(role);
    }

    g_string_append_printf(str, "{\"serviceName\":\"%s\",\"pid\":%d,\"allNames\":[%s]},",
      client->service_name ? client->service_name : "",
      pid,
      allowed_names.c_str());
}


/**
 *******************************************************************************
 * @brief Generate payload for service subscription response listing all
 *        available services and their pids.
 *
 * @param  table  IN  available_services table
 * @retval            allocated gchar*
 *******************************************************************************
 */
static gchar *
_LSHubSignalRegisterAllServices(GHashTable *table)
{
    LS_ASSERT(table != NULL);
    GString * str = g_string_new("{\"returnValue\":true,\"services\":[");

    g_hash_table_foreach(table, _LSHubSignalRegisterAllServicesItem, str);

    // trim off last comma
    g_string_truncate(str, str->len-1);

    g_string_append_printf(str, "]}");

    return g_string_free(str, FALSE);
}


/**
 ********************************************************************************
 * @brief Process a signal register message.
 *
 * @param  message  IN  signal register message
 ********************************************************************************/
static void
_LSHubHandleSignalRegister(_LSTransportMessage* message)
{
    LSError lserror;
    LSErrorInit(&lserror);

    const char *category = _LSTransportMessageGetCategory(message);
    const char *method = _LSTransportMessageGetMethod(message);
    _LSTransportClient *client = _LSTransportMessageGetClient(message);

    LOG_LS_DEBUG("%s: category: \"%s\", method: \"%s\", client: %p\n", __func__, category, method, client);

    LS_ASSERT(category != NULL);

    if (!LSHubIsClientAllowedToSubscribeSignal(client, category, method))
    {
        if (!_LSTransportSendReply(message,
                                   LS::Payload(R"({"returnValue":false, "errorCode":-1, "errorText":"Access denied"})"),
                                   &lserror))
        {
            LOG_LSERROR(MSGID_LSHUB_REG_REPLY_ERR, &lserror);
            LSErrorFree(&lserror);
        }
        return;
    }

    /* add to our category/method hash if registering category/method */
    if (method[0] != '\0')
    {
        /* method is optional for registration */
        std::string path = std::string(category) + "/" + method;
        _LSHubAddSignal(signal_map->method_map, path.c_str(), client);
    }
    else
    {
        _LSHubAddSignal(signal_map->category_map, category, client);
    }

    /* FIXME: we need to create a new "signal reply" function, so that we can
     * differentiate between method call replies and signal registration replies
     * for the shutdown logic */

    /* ACK the signal registration -- eventually we'll probably want to avoid
     * doing the extra translation in _LSMessageTranslateFromCall and send
     * all of the relevant info here including the category and path */

    if (strcmp(category, SERVICE_STATUS_CATEGORY) == 0 && method[0] == '\0')
    {
        /* ACK signal registration for methodless serviceStatus with current
         * status of all services */
        gchar * payload = _LSHubSignalRegisterAllServices(available_services);
        if (!_LSTransportSendReply(message, LS::Payload(payload), &lserror))
        {
            LOG_LSERROR(MSGID_LSHUB_REG_REPLY_ERR, &lserror);
            LSErrorFree(&lserror);
        }
        g_free(payload);
        return;
    }

    if (!_LSTransportSendReply(message, LS::Payload(R"({"returnValue":true})"), &lserror))
    {
        LOG_LSERROR(MSGID_LSHUB_REG_REPLY_ERR, &lserror);
        LSErrorFree(&lserror);
    }

    /* TODO: add reverse lookup */
}

/**
 ********************************************************************************
 * @brief Process a signal message (i.e., forward to all interested clients).
 *
 * @param  message  IN  signal message
 * @param  generated_by_hub  IN  true if signal was generated internally by hub
 ********************************************************************************/
static void
_LSHubHandleSignal(_LSTransportMessage *message, bool generated_by_hub)
{
    const char *category = _LSTransportMessageGetCategory(message);
    const char *method = _LSTransportMessageGetMethod(message);

    LS_ASSERT(category != NULL);
    LS_ASSERT(method != NULL);

    if (!generated_by_hub && !LSHubIsClientAllowedToSendSignal(_LSTransportMessageGetClient(message),
                                                               category, method))
    {
        return;
    }

    /* look up all clients that handle this category */
    _LSTransportClientMap *category_client_map = static_cast<_LSTransportClientMap *>(g_hash_table_lookup(signal_map->category_map, category));

    if (category_client_map)
    {
        _LSTransportClientMapForEach(category_client_map, (GHFunc)_LSHubSendSignal, message);
    }

    /* look up all clients that handle this category/method */
    std::string category_method = std::string(category) + "/" + method;
    _LSTransportClientMap *method_client_map =
            static_cast<_LSTransportClientMap *>(g_hash_table_lookup(signal_map->method_map, category_method.c_str()));
    if (method_client_map)
    {
        _LSTransportClientMapForEach(method_client_map, (GHFunc)_LSHubSendSignal, message);
    }
}

static bool
_SendMonitorAcceptClient(const _ClientId *monitor_id, const _ClientId *id, int fd, LSError *lserror)
{
    auto message = mk_ptr(_LSTransportMessageNewRef(LS_TRANSPORT_MESSAGE_DEFAULT_PAYLOAD_SIZE),
                          _LSTransportMessageUnref);

    _LSTransportMessageSetType(message.get(), _LSTransportMessageTypeMonitorAcceptClient);
    _LSTransportMessageSetFd(message.get(), fd);

    _LSTransportMessageIter iter;
    _LSTransportMessageIterInit(message.get(), &iter);

    if (!_LSTransportMessageAppendString(&iter, id->service_name) ||
        !_LSTransportMessageAppendString(&iter, id->local.name) ||
        !_LSTransportMessageAppendInvalid(&iter))
    {
        _LSErrorSet(lserror, MSGID_LS_OOM_ERR, -ENOMEM, "OOM");
        return false;
    }

    return _LSTransportSendMessage(message.get(), monitor->client, NULL, lserror);
}

/**
 *******************************************************************************
 * @brief Send a message to client telling it to connect to the monitor.
 *
 * @param  ignored_fd   IN  don't use this
 * @param  id           IN  client id
 * @param  monitor_id   IN  monitor's client id
 *******************************************************************************
 */
static void
_LSHubSendMonitorMessage(int ignored_fd, _ClientId *id, _ClientId *monitor_id)
{
    LSError lserror;
    LSErrorInit(&lserror);

    /* Skip sending the message to the monitor itself */
    if (id->is_monitor)
    {
        return;
    }

    LOG_LS_DEBUG("%s: client: %p\n", __func__, id->client);

    bool monitor_is_connected = true;
    _LSTransportMessageIter iter;

    const char *unique_name = nullptr;
    if (monitor_id)
        unique_name = monitor_id->local.name;

    if (!unique_name)
    {
        monitor_is_connected = false;
    }

    /* get the unique name for the client and add send it as part of the message */
    auto monitor_message = mk_ptr(_LSTransportMessageNewRef(LS_TRANSPORT_MESSAGE_DEFAULT_PAYLOAD_SIZE),
                                  _LSTransportMessageUnref);

    _LSTransportMessageSetType(monitor_message.get(),
                               monitor_is_connected ?  _LSTransportMessageTypeMonitorConnected
                                                    :  _LSTransportMessageTypeMonitorNotConnected);

    _LSTransportMessageIterInit(monitor_message.get(), &iter);
    if (!_LSTransportMessageAppendString(&iter, unique_name) || !_LSTransportMessageAppendInvalid(&iter))
    {
        return;
    }

    /* set up the connection to the monitor if it exists and we're local */
    if (monitor_is_connected)
    {
        int socket_vector[2] = { -1, -1 };
        if (-1 == socketpair(AF_UNIX, SOCK_STREAM, 0, socket_vector))
        {
            LOG_LS_ERROR(MSGID_LSHUB_SERVICE_CONNECT_ERROR, 2,
                         PMLOGKFV("ERROR_CODE", "%d", errno),
                         PMLOGKS("ERROR", g_strerror(errno)),
                         "%s: Failed to create sockets to monitor "
                         "%s", __func__, id->service_name);
            return;
        }

        /* go ahead and set the fd, even if it's -1 */
        _LSTransportMessageSetFd(monitor_message.get(), socket_vector[0]);

        // The ownership of socket_vector[1] is transfered to the function, and
        // it's responsible for closing it in case of an error.
        if (!_SendMonitorAcceptClient(monitor_id, id, socket_vector[1],
                                      &lserror))
        {
            LOG_LSERROR(MSGID_LSHUB_SENDMSG_ERROR, &lserror);
            LSErrorFree(&lserror);
            return;
        }
    }

    if (!_LSTransportSendMessage(monitor_message.get(), id->client, NULL, &lserror))
    {
        LOG_LSERROR(MSGID_LSHUB_SENDMSG_ERROR, &lserror);
        LSErrorFree(&lserror);
    }
}

static bool _LSHubCheckClientIsMonitor(_LSTransportClient *client)
{
    if (!client)
    {
        LOG_LS_ERROR(MSGID_LSHUB_NO_CLIENT, 0, "Unable to get monitor client");
        return false;
    }

    if (g_conf_security_enabled && !LSHubIsClientMonitor(client))
    {
        G_GNUC_UNUSED const _LSTransportCred *cred = _LSTransportClientGetCred(client);
        LOG_LS_ERROR(MSGID_LSHUB_NO_MONITOR_MESSAGE, 2,
                     PMLOGKS("EXE", _LSTransportCredGetExePath(cred)),
                     PMLOGKFV("PID", LS_PID_PRINTF_FORMAT, LS_PID_PRINTF_CAST(_LSTransportCredGetPid(cred))),
                     "Monitor message not sent by monitor (cmdline: %s)",
                     _LSTransportCredGetCmdLine(cred));
        return false;
    }

    return true;
}

/**
 *******************************************************************************
 * @brief Process a monitor request message by sending out messages to each
 * client telling them to connect.
 *
 * @param  message  IN  monitor request message
 *******************************************************************************
 */
static void
_LSHubHandleMonitorRequest(_LSTransportMessage *message)
{
    /* get the unique name for the monitor */
    _LSTransportClient *monitor_client = _LSTransportMessageGetClient(message);;

    if (!_LSHubCheckClientIsMonitor(monitor_client))
        return;

    /* mark this client as the monitor */
    _ClientId *id = static_cast<_ClientId *>(g_hash_table_lookup(connected_clients.by_fd, GINT_TO_POINTER(monitor_client->channel.fd)));

    if (!id)
    {
        LOG_LS_WARNING(MSGID_LSHUB_NO_MONITOR, 0, "Unable to find monitor in connected client map");
        return;
    }

    /* mark this client as the monitor */
    id->is_monitor = true;
    _LSHubClientIdLocalRef(id);
    monitor = id;

    if (monitor_client->unique_name)
    {
        /* forward the message to all connected clients */
        g_hash_table_foreach(connected_clients.by_fd, (GHFunc)_LSHubSendMonitorMessage, monitor);
    }
    else
    {
        LOG_LS_ERROR(MSGID_LSHUB_UNAME_ERROR, 0,
                  "We were expecting the monitor to have the monitor's unique_name, monitor_client: %p", monitor_client);
    }
}

/**
 *******************************************************************************
 * @brief Send the status of the monitor (used when a client first comes up).
 *
 * @param  message  IN  message with client info
 *******************************************************************************
 */
static void
_LSHubSendMonitorStatus(_LSTransportMessage *message)
{
    _LSTransportClient *client = message->client;

    _ClientId *id = static_cast<_ClientId *>(g_hash_table_lookup(connected_clients.by_fd, GINT_TO_POINTER(client->channel.fd)));

    if (!id)
    {
        /* This can happen if the RequestName fails */
        LOG_LS_ERROR(MSGID_LSHUB_NO_FD, 2,
                     PMLOGKS("APP_ID", client->service_name ? client->service_name : "(null)"),
                     PMLOGKS("UNIQUE_NAME", client->unique_name ? client->unique_name : "(null)"),
                     "Unable to find fd: %d in connected_clients hash, client: %p",
                     client->channel.fd, client);
        //LS_ASSERT(id != NULL);
        return;
    }

    // If no monitor, so we send an empty name message
    _LSHubSendMonitorMessage(-1, id, monitor);
}

/**
 *******************************************************************************
 * @brief Process a "QueryServiceStatus" message and send a reply with the
 * state of the service.
 *
 * @param  message  IN  query service status message
 *******************************************************************************
 */
static void
_LSHubHandleQueryServiceStatus(const _LSTransportMessage *message)
{
    LS_ASSERT(_LSTransportMessageGetType(message) == _LSTransportMessageTypeQueryServiceStatus);

    LSError lserror;
    LSErrorInit(&lserror);

    _LSTransportMessageIter iter;

    _LSTransportClient *reply_client = _LSTransportMessageGetClient(message);
    int available = 0;
    const char *service_name = NULL;

    _LSTransportMessageIterInit((_LSTransportMessage*)message, &iter);
    _LSTransportMessageGetString(&iter, &service_name);

    available = g_hash_table_lookup(available_services, service_name) ? 1 : 0;
    if (available == 0)
    {
        for (const auto& name : GetServiceRedirectionVariants(service_name))
        {
            /* look up service name in available list */
            if (g_hash_table_lookup(available_services, name.c_str()))
            {
                available = 1;
                break;
            }
        }
    }

    /* for legacy support for subscriptions, we allow asking for service
     * status with a unique name as the "service name" */
    if (available == 0 && g_hash_table_lookup(connected_clients.by_unique_name, service_name))
    {
        available = 1;
    }

    /* construct the reply -- reply_serial + available val */
    _LSTransportMessage *reply = _LSTransportMessageNewRef(sizeof(LSMessageToken) + sizeof(available));
    reply->raw->header.is_public_bus = message->raw->header.is_public_bus;
    _LSTransportMessageSetType(reply, _LSTransportMessageTypeQueryServiceStatusReply);

    LSMessageToken msg_serial = _LSTransportMessageGetToken(message);
    char *body = _LSTransportMessageGetBody(reply);

    memcpy(body, &msg_serial, sizeof(msg_serial));
    body += sizeof(msg_serial);
    memcpy(body, &available, sizeof(available));

    if (!_LSTransportSendMessage(reply, reply_client, NULL, &lserror))
    {
        LOG_LSERROR(MSGID_LSHUB_SENDMSG_ERROR, &lserror);
        LSErrorFree(&lserror);
    }

    _LSTransportMessageUnref(reply);
}

static void send_service_category_reply(const _LSTransportMessage *message, const char *payload)
{
    /* construct the reply -- reply_serial + payload */
    _LSTransportMessage *reply = _LSTransportMessageNewRef(LS_TRANSPORT_MESSAGE_DEFAULT_PAYLOAD_SIZE);
    reply->raw->header.is_public_bus = message->raw->header.is_public_bus;
    _LSTransportMessageSetType(reply, _LSTransportMessageTypeQueryServiceCategoryReply);

    _LSTransportMessageIter iter;
    _LSTransportMessageIterInit(reply, &iter);

    do {
        LSError lserror;
        LSErrorInit(&lserror);

        LSMessageToken msg_serial = _LSTransportMessageGetToken(message);
        static_assert(sizeof(LSMessageToken) <= 8, "LSMessageToken doesn't fit into 64 bits");
        if (!_LSTransportMessageAppendInt64(&iter, msg_serial)) break;
        if (!_LSTransportMessageAppendString(&iter, payload)) break;

        if (!_LSTransportSendMessage(reply, _LSTransportMessageGetClient(message),
                                     NULL, &lserror))
        {
            LOG_LSERROR(MSGID_LSHUB_SENDMSG_ERROR, &lserror);
            LSErrorFree(&lserror);
        }

    } while (0);

    _LSTransportMessageUnref(reply);
}

static jvalue_ref DumpCategories(const _ClientId *id, const char *category)
{
    jvalue_ref payload = jobject_create();
    if (!payload)
    {
        LOG_LS_ERROR(MSGID_LSHUB_OOM_ERR, 0, "Out of memory");
        return NULL;
    }

    if (!category || !category[0])
    {
        /* If no category was given originally, the client is interested
         * in every category.
         *
         * Reply payload: {"/a": ["foo", "bar"], "/b": ["baz"]}
         */

        GHashTableIter cat_it;
        g_hash_table_iter_init(&cat_it, id->categories);

        const char *registered_category = NULL;
        const GSList *method_list = NULL;
        while (g_hash_table_iter_next(&cat_it, (gpointer *) &registered_category, (gpointer *) &method_list))
        {
            jvalue_ref functions = jarray_create(0);
            for (; method_list; method_list = g_slist_next(method_list))
                jarray_append(functions, jstring_create(static_cast<const char *>(method_list->data)));
            jobject_put(payload, jstring_create(registered_category), functions);
        }
    }
    else
    {
        const GSList *method_list = static_cast<const GSList *>(g_hash_table_lookup(id->categories, category));
        if (method_list)
        {
            /* The specific category has been found.
             *
             * Reply payload: {"/a": ["foo", "bar"]}
             */

            jvalue_ref functions = jarray_create(0);
            for (; method_list; method_list = g_slist_next(method_list))
                jarray_append(functions, jstring_create(static_cast<const char* >(method_list->data)));
            jobject_put(payload, jstring_create(category), functions);
        }

        /* No such category is registered. Reply payload: {} */
    }

    return payload;
}

/**
 *******************************************************************************
 * @brief Process a "QueryServiceCategory" message and send a reply with the
 * registered categories of the service.
 *
 * @param  message  IN  query service categories
 *******************************************************************************
 */
static void
_LSHubHandleQueryServiceCategory(const _LSTransportMessage *message)
{
    LS_ASSERT(_LSTransportMessageGetType(message) == _LSTransportMessageTypeQueryServiceCategory);

    _LSTransportMessageIter iter;

    const char *service_name = NULL;
    const char *category = NULL;

    _LSTransportMessageIterInit((_LSTransportMessage*)message, &iter);

    _LSTransportMessageGetString(&iter, &service_name);
    _LSTransportMessageIterNext(&iter);
    _LSTransportMessageGetString(&iter, &category);
    _LSTransportMessageIterNext(&iter);

    /* look up service name in available list */
    _ClientId *id = static_cast<_ClientId *>(g_hash_table_lookup(available_services, service_name));
    if (!id || !id->categories)
        send_service_category_reply(message, "{}");
    else
    {
        jvalue_ref payload = DumpCategories(id, category);
        if (payload)
        {
            send_service_category_reply(message, jvalue_tostring_simple(payload));
            j_release(&payload);
        }
    }

    // Remember the client for further notifications
    char *signal_category = NULL;
    if (category && category[0])
        signal_category = g_strdup_printf(LUNABUS_WATCH_CATEGORY_CATEGORY "/%s%s", service_name, category);
    else
        signal_category = g_strdup_printf(LUNABUS_WATCH_CATEGORY_CATEGORY "/%s", service_name);

    _LSHubAddSignal(signal_map->category_map, signal_category, _LSTransportMessageGetClient(message));

    g_free(signal_category);
}

/**
 *******************************************************************************
 * @brief Replies with a message of all connected clients.
 *
 * @param  message  IN  list clients message
 *******************************************************************************
 */
static void
_LSHubHandleListClients(const _LSTransportMessage *message)
{
    LS_ASSERT(_LSTransportMessageGetType(message) == _LSTransportMessageTypeListClients);

    gpointer key = NULL;
    gpointer value = NULL;

    LSError lserror;
    LSErrorInit(&lserror);

    _LSTransportMessageIter iter;
    GHashTableIter hash_iter;

    _LSTransportClient *reply_client = _LSTransportMessageGetClient(message);

    auto reply = mk_ptr<_LSTransportMessage>(_LSTransportMessageNewRef(LS_TRANSPORT_MESSAGE_DEFAULT_PAYLOAD_SIZE),
                                             _LSTransportMessageUnref);
    reply->raw->header.is_public_bus = message->raw->header.is_public_bus;
    _LSTransportMessageSetType(reply.get(), _LSTransportMessageTypeListClientsReply);

    _LSTransportMessageIterInit(reply.get(), &iter);
    g_hash_table_iter_init(&hash_iter, connected_clients.by_unique_name);

    /* TODO: set reply serial? */

    /* iterate over entire hash table of connected clients */
    while (g_hash_table_iter_next(&hash_iter, &key, &value))
    {
        const _LSTransportCred *cred = NULL;
        _Service *service = NULL;

        char *unique_name = static_cast<char *>(key);
        _ClientId *id = static_cast<_ClientId *>(value);

        if (!_LSTransportMessageAppendString(&iter, unique_name) ||
            !_LSTransportMessageAppendString(&iter, id->service_name))
            return;

        cred = _LSTransportClientGetCred(id->client);

        if (!_LSTransportMessageAppendInt32(&iter, _LSTransportCredGetPid(cred)) ||
            !_LSTransportMessageAppendString(&iter, _LSTransportCredGetExePath(cred)))
            return;

        if (id->service_name)
        {
            service = SecurityData::CurrentSecurityData().services.Lookup(id->service_name);
        }

        if (service)
        {
            if (!_LSTransportMessageAppendString(&iter, service->is_dynamic ? "dynamic" : "static"))
                return;
        }
        else
        {
            if (!_LSTransportMessageAppendString(&iter, "unknown/client only"))
                return;
        }
    }

    if (!_LSTransportMessageAppendInvalid(&iter))
        return;

    if (!_LSTransportSendMessage(reply.get(), reply_client, NULL, &lserror))
    {
        LOG_LSERROR(MSGID_LSHUB_SENDMSG_ERROR, &lserror);
        LSErrorFree(&lserror);
    }
}

/**
 *******************************************************************************
 * @brief Replies with series of messages with security data dump.
 *
 * @param  message  IN  request message
 *******************************************************************************
 */
static void
_LSHubHandleDumpHubData(const _LSTransportMessage *message)
{
    LS_ASSERT(_LSTransportMessageGetType(message) == _LSTransportMessageTypeDumpHubData);

    _LSTransportClient *monitor_client = _LSTransportMessageGetClient(message);
    if (!_LSHubCheckClientIsMonitor(monitor_client))
        return;

    // Send a chunk of text back to the monitor.
    auto send_reply = [message, monitor_client](const char *data)
    {
        auto reply = mk_ptr(_LSTransportMessageNewRef(LS_TRANSPORT_MESSAGE_DEFAULT_PAYLOAD_SIZE),
                            _LSTransportMessageUnref);
        reply->raw->header.is_public_bus = message->raw->header.is_public_bus;
        _LSTransportMessageSetType(reply.get(), _LSTransportMessageTypeDumpHubDataReply);

        _LSTransportMessageIter iter;
        _LSTransportMessageIterInit(reply.get(), &iter);

        if (data && !_LSTransportMessageAppendString(&iter, data))
            return false;

        if (!_LSTransportMessageAppendInvalid(&iter))
            return false;

        LS::Error lserror;
        if (!_LSTransportSendMessage(reply.get(), monitor_client, NULL, lserror.get()))
        {
            LOG_LSERROR(MSGID_LSHUB_SENDMSG_ERROR, lserror.get());
            return false;
        }

        return true;
    };

    const auto &data = SecurityData::CurrentSecurityData();

    {
        auto dump = data.services.DumpCsv();
        send_reply(dump.c_str());
    }

    {
        auto dump = data.roles.DumpCsv();
        send_reply(dump.c_str());
    }

    {
        auto dump = data.permissions.DumpCsv();
        send_reply(dump.c_str());
    }

    {
        auto dump = data.groups.DumpRequiredCsv();
        send_reply(dump.c_str());
    }

    {
        auto dump = data.groups.DumpProvidedCsv();
        send_reply(dump.c_str());
    }

    // Dump required trust levels
    {
        auto dump = data.groups.DumpRequiredTrustLevelCsv();
        send_reply(dump.c_str());
    }

    // Dump provided trust levels
    {
        auto dump = data.groups.DumpProvidedTrustLevelCsv();
        send_reply(dump.c_str());
    }

    send_reply(nullptr);
}

static void
_LSHubHandlePushRole(_LSTransportMessage *message)
{
    LS_ASSERT(_LSTransportMessageGetType(message) == _LSTransportMessageTypePushRole);

    LSError lserror;
    LSErrorInit(&lserror);

    _LSTransportMessageIter iter;
    const char *role_path = NULL;
    int32_t ret_code = LS_TRANSPORT_PUSH_ROLE_SUCCESS;

    /* If security is not enabled, then we just return success */
    if (g_conf_security_enabled)
    {
        _LSTransportClient *sender_client = _LSTransportMessageGetClient(message);

        /* Get the path to the role file */
        _LSTransportMessageIterInit(message, &iter);

        LS_ASSERT(_LSTransportMessageIterHasNext(&iter));

        bool role_ret = _LSTransportMessageGetString(&iter, &role_path);

        if (!role_ret || !role_path)
        {
            LOG_LS_ERROR(MSGID_LSHUB_NO_ROLE_PATH, 2,
                         PMLOGKS("APP_ID", _LSTransportMessageGetSenderServiceName(message)),
                         PMLOGKS("UNIQUE_NAME", _LSTransportMessageGetSenderUniqueName(message)),
                         "Unable to get role path");
            return;
        }

        if (!LSHubPushRole(sender_client, role_path, message->raw->header.is_public_bus, &lserror))
        {
            G_GNUC_UNUSED const _LSTransportCred *cred = _LSTransportClientGetCred(sender_client);

            ret_code = lserror.error_code;
            LOG_LS_ERROR(MSGID_LSHUB_CANT_PUSH_ROLE, 2,
                         PMLOGKS("EXE", _LSTransportCredGetExePath(cred)),
                         PMLOGKFV("PID", LS_PID_PRINTF_FORMAT, LS_PID_PRINTF_CAST(_LSTransportCredGetPid(cred))),
                         "Unable to push role (cmdline: %s)",
                         _LSTransportCredGetCmdLine(cred));
            LOG_LSERROR(MSGID_LSHUB_CANT_PUSH_ROLE, &lserror);
        }
    }

    _LSTransportClient *reply_client = _LSTransportMessageGetClient(message);

    auto reply = mk_ptr<_LSTransportMessage>(_LSTransportMessageNewRef(LS_TRANSPORT_MESSAGE_DEFAULT_PAYLOAD_SIZE),
                                             _LSTransportMessageUnref);
    reply->raw->header.is_public_bus = message->raw->header.is_public_bus;
    _LSTransportMessageSetType(reply.get(), _LSTransportMessageTypePushRoleReply);

    _LSTransportMessageIterInit(reply.get(), &iter);

    /* TODO: set reply serial ? */

    if (!_LSTransportMessageAppendInt32(&iter, ret_code)) return;

    if (ret_code != LS_TRANSPORT_PUSH_ROLE_SUCCESS)
    {
        /* We didn't free the lserror above when printed */
        if (!_LSTransportMessageAppendString(&iter, lserror.message)) return;
    }

    if (!_LSTransportMessageAppendInvalid(&iter)) return;

    if (LSErrorIsSet(&lserror))
    {
        LSErrorFree(&lserror);
    }

    if (!_LSTransportSendMessage(reply.get(), reply_client, NULL, &lserror))
    {
        LOG_LSERROR(MSGID_LSHUB_SENDMSG_ERROR, &lserror);
        LSErrorFree(&lserror);
    }
}


static void free_method_list(gpointer method_list)
{
    g_slist_free_full(static_cast<_GSList*>(method_list), g_free);
}

static void
_LSHubAppendCategory(const char *service_name, const char *category,
                     GSList *methods, bool is_public_bus)
{
    _ClientId *id = static_cast<_ClientId *>(g_hash_table_lookup(available_services, service_name));
    LS_ASSERT(id);

    // TODO: Is locking required?
    if (!id->categories)
        id->categories = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, free_method_list);

    char *orig_category = NULL;
    GSList *orig_method_list = NULL;

    if (g_hash_table_lookup_extended(id->categories, category,
                                     (gpointer *) &orig_category, (gpointer *) &orig_method_list))
    {
        g_hash_table_steal(id->categories, category);
        orig_method_list = g_slist_concat(orig_method_list, methods);
        g_hash_table_insert(id->categories, orig_category, orig_method_list);
    }
    else
    {
        g_hash_table_insert(id->categories, g_strdup(category), methods);
    }

    // Send signal about the update to the interested clients.
    {
        // Without specifying category
        jvalue_ref payload = DumpCategories(id, NULL);
        if (payload)
        {
            char *signal_category = g_strdup_printf(LUNABUS_WATCH_CATEGORY_CATEGORY "/%s", service_name);
            _LSTransportMessage *message = LSTransportMessageSignalNewRef(signal_category,
                                                                          "change",
                                                                          jvalue_tostring_simple(payload),
                                                                          is_public_bus);
            _LSHubHandleSignal(message, true);
            _LSTransportMessageUnref(message);
            g_free(signal_category);
            j_release(&payload);
        }
    }

    {
        // To the specific category listeners
        jvalue_ref payload = DumpCategories(id, category);
        if (payload)
        {
            char *signal_category = g_strdup_printf(LUNABUS_WATCH_CATEGORY_CATEGORY "/%s%s", service_name, category);
            _LSTransportMessage *message = LSTransportMessageSignalNewRef(signal_category,
                                                                          "change",
                                                                          jvalue_tostring_simple(payload),
                                                                          is_public_bus);
            _LSHubHandleSignal(message, true);
            _LSTransportMessageUnref(message);
            g_free(signal_category);
            j_release(&payload);
        }
    }
}

static void
_LSHubHandleAppendCategory(_LSTransportMessage *message)
{
    LS_ASSERT(_LSTransportMessageGetType(message) == _LSTransportMessageTypeAppendCategory);

    const char *service_name = _LSTransportClientGetServiceName(_LSTransportMessageGetClient(message));

    _LSTransportMessageIter iter;
    _LSTransportMessageIterInit(message, &iter);

    LS_ASSERT(_LSTransportMessageIterHasNext(&iter));
    const char *category = NULL;
    _LSTransportMessageGetString(&iter, &category);
    LS_ASSERT(category);
    _LSTransportMessageIterNext(&iter);

    GSList *method_list = NULL;
    for (; _LSTransportMessageIterHasNext(&iter); _LSTransportMessageIterNext(&iter))
    {
        const char *method_name = NULL;
        _LSTransportMessageGetString(&iter, &method_name);
        LS_ASSERT(method_name);
        method_list = g_slist_prepend(method_list, g_strdup(method_name));
    }

    if (method_list)
        _LSHubAppendCategory(service_name,
                             category,
                             method_list,
                             message->raw->header.is_public_bus);
}

/**
 *******************************************************************************
 * @brief Process incoming messages from underlying transport.
 *
 * @param  message  IN  incoming message
 * @param  context  IN  unused
 *
 * @retval LSMessageHandlerResultHandled
 *******************************************************************************
 */
static LSMessageHandlerResult
_LSHubHandleMessage(_LSTransportMessage* message, void *context)
{
    switch (_LSTransportMessageGetType(message))
    {
    case _LSTransportMessageTypeRequestName:
        if (_LSHubHandleRequestName(message))
        {
            /* tell the connecting client whether we have a monitor */
            _LSHubSendMonitorStatus(message);
        }
        break;

    case _LSTransportMessageTypeNodeUp:
        _LSHubHandleNodeUp(message);
        break;

    case _LSTransportMessageTypeListClients:
        _LSHubHandleListClients(message);
        break;

    case _LSTransportMessageTypeDumpHubData:
        _LSHubHandleDumpHubData(message);
        break;

    case _LSTransportMessageTypeQueryName:
        _LSHubHandleQueryName(message);
        break;

    case _LSTransportMessageTypeQueryProxyName:
        _LSHubHandleQueryProxyName(message);
        break;

    case _LSTransportMessageTypeSignalRegister:
        _LSHubHandleSignalRegister(message);
        break;

    case _LSTransportMessageTypeSignalUnregister:
        _LSHubHandleSignalUnregister(message);
        break;

    case _LSTransportMessageTypeSignal:
        _LSHubHandleSignal(message, false);
        break;

    case _LSTransportMessageTypeMonitorRequest:
        _LSHubHandleMonitorRequest(message);
        break;

    case _LSTransportMessageTypeQueryServiceStatus:
        _LSHubHandleQueryServiceStatus(message);
        break;

    case _LSTransportMessageTypeQueryServiceCategory:
        _LSHubHandleQueryServiceCategory(message);
        break;

    case _LSTransportMessageTypePushRole:
        _LSHubHandlePushRole(message);
        break;

    case _LSTransportMessageTypeAppendCategory:
        _LSHubHandleAppendCategory(message);
        break;

    case _LSTransportMessageTypeHubMethodCall:
        HubService::instance().HandleMethodCall(message);
        break;

    case _LSTransportMessageTypeMethodCall:
    case _LSTransportMessageTypeReply:
    case _LSTransportMessageTypeReplyWithFd:
    default:
        LOG_LS_ERROR(MSGID_LSHUB_MEMORY_ERR, 0, "Received unhandled message type: %d", _LSTransportMessageGetType(message));
        break;
    }

    return LSMessageHandlerResultHandled;
}

/**
 *******************************************************************************
 * @brief Checks to see if the hub is already running. It saves the PID
 * in a file and locks it. It may call exit() if it encounters an error.
 *
 * @retval  true, if the hub is running
 * @retval  false, if the hub isn't running
 *******************************************************************************
 */
static bool
_HubIsRunning()
{
    return LSIsRunning(*pid_dir, HUB_LOCK_FILENAME);
}

/**
 ********************************************************************************
 * @brief Use the options from the conf file unless we have overriden then
 * on the command line.
 *
 * @param cmdline_pid_dir            IN ptr to pid dir path from command line
 *******************************************************************************
 */
static void
_ProcessConfFileOptions(char **cmdline_pid_dir)
{
    if (cmdline_pid_dir && *cmdline_pid_dir)
    {
        pid_dir = cmdline_pid_dir;
    }
    else
    {
        pid_dir = &g_conf_pid_dir;
    }

    if (g_mkdir_with_parents(*pid_dir, 0755) == -1)
    {
        LOG_LS_ERROR(MSGID_LSHUB_MKDIR_ERROR, 3,
                     PMLOGKS("PATH", *pid_dir),
                     PMLOGKFV("ERROR_CODE", "%d", errno),
                     PMLOGKS("ERROR", g_strerror(errno)),
                     "Unable to create directory");
    }
}


#ifdef UNIT_TESTS
int main_hub(int argc, char *argv[])
#else
int main(int argc, char *argv[])
#endif
{
    static gboolean daemonize = FALSE;
    static gboolean debug = FALSE;
    static char *boot_file_name = NULL;
    static char *cmdline_pid_dir = NULL;

    static GOptionEntry opt_entries[] =
    {
        {"debug", 'd', 0, G_OPTION_ARG_NONE, &debug, "Log debug information", NULL},
        {"service-dir", 's', 0, G_OPTION_ARG_FILENAME, &service_dir, "Directory where service files are stored", "/some/path"},
        {"pid-dir", 'i', 0, G_OPTION_ARG_FILENAME, &cmdline_pid_dir, "Directory where the pid file is stored (default /var/run)", "/some/path"},
        {"conf", 'c', 0, G_OPTION_ARG_FILENAME, &conf_file, "MANDATORY: Path to config file", "/some/path/ls.conf"},
        {"boot-file", 'b', 0, G_OPTION_ARG_FILENAME, &boot_file_name, "Create specified file when done booting", "/some/path/file"},
        {"distinct-log", 'm', 0, G_OPTION_ARG_NONE, &use_distinct_log_file, "Log to distinct context log file (set in /etc/pmlog.d/ls-hubd.conf)", NULL},
        {"daemon", 'a', 0, G_OPTION_ARG_NONE, &daemonize, "Run as daemon (fork and run in background)", NULL},
        { NULL }
    };

    srand(time(nullptr));

    GOptionContext *opt_context = g_option_context_new("- Luna Service Hub");
    g_option_context_add_main_entries(opt_context, opt_entries, NULL);

    GError *gerror = nullptr;
    if (!g_option_context_parse(opt_context, &argc, &argv, &gerror))
    {
        LOG_LS_ERROR(MSGID_LSHUB_BAD_PARAMS, 2,
                     PMLOGKFV("ERROR_CODE", "%d", gerror->code),
                     PMLOGKS("ERROR", gerror->message),
                     "Error processing commandline args: \"%s\"", gerror->message);
        g_error_free(gerror);
        exit(EXIT_FAILURE);
    }

    g_option_context_free(opt_context);

    const char *log_context_name = NULL;
    if (use_distinct_log_file)
    {
        log_context_name = HUB_LOG_CONTEXT_DISTINCT;
    }
    else if (debug)
    {
        log_context_name = HUB_LOG_CONTEXT_DEBUG;
    }
    else
    {
        log_context_name = HUB_LOG_CONTEXT;
    }

    PmLogGetContext(log_context_name, &pm_log_context);
    PmLogSetLibContext(pm_log_context);

    if (NULL == conf_file)
    {
        LOG_LS_ERROR(MSGID_LSHUB_CONF_FILE_ERROR, 0,
                     "Mandatory configuration file (-c/--conf) not provided!");
        exit(EXIT_FAILURE);
    }

    if (daemonize)
    {
        if (daemon(1, 1) < 0)
        {
            LOG_LS_CRITICAL(MSGID_LSHUB_UNABLE_TO_START_DAEMON, 2,
                            PMLOGKFV("ERROR_CODE", "%d", errno),
                            PMLOGKS("ERROR", g_strerror(errno)),
                            "Unable to become a daemon: %s", g_strerror(errno));
        }
    }

    LOG_LS_DEBUG("Hub starting\n");

    /* TODO: turn into a daemon */

    /* config file
     *     - inits and fills the dynamic service map
     *     - inits and fills the role map and permission map
     *     - inits and fills the security groups tree */
    ConfigSetFilePath(conf_file);
    ConfigUpdateSecurity(false);

    auto &config_thread = ConfigGetParserThread();

    /* config file */
    LS::Error lserror;
    if (!ConfigSetupInotify(lserror))
    {
        LOG_LSERROR(MSGID_LSHUB_INOTIFY_ERR, lserror);
        LSErrorFree(lserror);
    }

    /* Command-line options override the settings from the conf file */
    _ProcessConfFileOptions(&cmdline_pid_dir);

    /* Don't allow multiple instances to run */
    if (_HubIsRunning())
    {
        LOG_LS_ERROR(MSGID_LSHUB_ALREADY_RUNNING, 0, "An instance of the hub is already running\n");
        exit(EXIT_FAILURE);
    }

    /* dynamic service state map */
    if (!DynamicServiceInitStateMap(lserror))
    {
        LOG_LSERROR(MSGID_LSHUB_STATE_MAP_ERR, lserror);
        LSErrorFree(lserror);
    }

    /* init data structures */
    pending = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, _LSHubClientIdLocalUnrefVoid);
    available_services = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, _LSHubClientIdLocalUnrefVoid);

    connected_clients.by_fd = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, _LSHubClientIdLocalUnrefVoid);
    connected_clients.by_unique_name = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, _LSHubClientIdLocalUnrefVoid);

    signal_map = _SignalMapNew();

    try
    {
        LSTransportHandlers hubHandlers = {
            .message_failure_handler = NULL,
            .message_failure_context = NULL,
            .disconnect_handler = _LSHubHandleDisconnect,
            .disconnect_context = NULL,
            .msg_handler = _LSHubHandleMessage,
            .msg_context = NULL,
        };

        HubLane lane(HUB_NAME, hubHandlers);

        const char *hub_local_addr = _LSGetHubLocalSocketAddress();

        LOG_LS_DEBUG("Using socket path: %s", hub_local_addr);

        lane.AttachLocalListener(hub_local_addr, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);

#if !defined(BUILD_FOR_DESKTOP)
        const char *event = "READY=1\nSTATUS=hubd ready event notified";

        if (sd_notify(0, event) <= 0)
        {
            LOG_LS_ERROR(MSGID_LSHUB_UPSTART_ERROR, 0, "Unable to send systemd ready event");
        }
#endif

        if (boot_file_name)
        {
            char *tmp = g_strdup(boot_file_name);
            char *dir = dirname(tmp);   /* can modify its arg, so we pass a copy */

            if (g_mkdir_with_parents(dir, 0755) == -1)
            {
                LOG_LS_ERROR(MSGID_LSHUB_MKDIR_ERROR, 3,
                        PMLOGKS("PATH", dir),
                        PMLOGKFV("ERROR_CODE", "%d", errno),
                        PMLOGKS("ERROR", g_strerror(errno)),
                        "Unable to create directory");
            }
            else
            {
                FILE *boot_file = fopen(boot_file_name, "w");

                if (!boot_file)
                {
                    LOG_LS_ERROR(MSGID_LSHUB_MKDIR_ERROR, 3,
                            PMLOGKS("PATH", boot_file_name),
                            PMLOGKFV("ERROR_CODE", "%d", errno),
                            PMLOGKS("ERROR", g_strerror(errno)),
                            "Unable to open boot file");
                }
                else
                {
                    fclose(boot_file);
                }
            }
            g_free(tmp);
        }

        if (!SetupWatchdog(lserror))
        {
            LOG_LSERROR(MSGID_LSHUB_WATCHDOG_ERR, lserror);
            LSErrorFree(lserror);
        }

        HubLane::Run();
    }
    catch (LS::Error& e)
    {
        LOG_LSERROR(MSGID_LSHUB_SPAWN_ERR, e.get());
    }

    _SignalMapFree(signal_map);

    if (pending) g_hash_table_destroy(pending);
    if (available_services) g_hash_table_destroy(available_services);
    if (dynamic_service_states) g_hash_table_destroy(dynamic_service_states);
    if (connected_clients.by_fd) g_hash_table_destroy(connected_clients.by_fd);
    if (connected_clients.by_unique_name) g_hash_table_destroy(connected_clients.by_unique_name);

    ConfigCleanup();
    config_thread.join();

    if (boot_file_name) unlink(boot_file_name);

    return 0;
}

/**
 * @} END OF LunaServiceHub
 * @endcond
 */
