// Copyright (c) 2008-2018 LG Electronics, Inc.
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
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <pbnjson.hpp>

#include "utils.h"
#include "transport.h"
#include "clock.h"
#include "monitor_queue.h"
#include "json_output.hpp"
#include "debug_methods.h"
#include "transport_priv.h"

#define DYNAMIC_SERVICE_STR         "dynamic"
#define STATIC_SERVICE_STR          "static"
#define SUBSCRIPTION_DEBUG_METHOD   "/com/palm/luna/private/subscriptions"
#define MALLOC_DEBUG_METHOD         "/com/palm/luna/private/mallinfo"

#define MONITOR_PID_NAME            "ls-monitor.pid"

#define TERMINAL_WIDTH_DEFAULT  80
#define TERMINAL_WIDTH_WIDE     100
#define HEADER_WIDTH_DEFAULT    45

typedef struct LSMonitorListInfo
{
    char *unique_name;
    char *service_name;
    int32_t pid;
    char *exe_path;
    char *service_type;
} _LSMonitorListInfo;

typedef struct SubscriptionReplyData
{
    GSList **reply_list;
    int total_replies;
} _SubscriptionReplyData;

static GHashTable *dup_hash_table;

static const char *list_servicename_methods = NULL;
static const char *get_servicename_api_version = NULL;
static const char *message_filter_str = NULL;
static std::unique_ptr<JsonOutputFormatter> json_formatter;
static gboolean list_clients = false;
static gboolean list_subscriptions = false;
static gboolean list_malloc = false;
static gboolean debug_output = false;
static gboolean compact_output = false;
static gboolean json_output = false;
static gboolean two_line_output = false;
static gboolean sort_by_timestamps = false;
static gboolean dump_hub_data = false;
static GMainLoop *mainloop = NULL;
static int exit_code = EXIT_SUCCESS;

static std::string ls_monitor_service_name = MONITOR_NAME;

static uint32_t terminal_width = TERMINAL_WIDTH_DEFAULT;

static _LSTransport *transport = NULL;
static GSList *sub_replies = NULL;
static _LSMonitorQueue *queue = NULL;

/* time1 - time2 */
double
_LSMonitorTimeDiff(const struct timespec *time1, const struct timespec *time2)
{
    double diff_time;

    /* local variable because we might modify it */
    long time1_nsec = time1->tv_nsec;

    diff_time = (double)(time1->tv_sec - time2->tv_sec);

    if (time1->tv_nsec < time2->tv_nsec) {
        diff_time--;
        time1_nsec = time1->tv_nsec + 1000000000;
    }
    diff_time += ((double)(time1_nsec - time2->tv_nsec) / (double)(1000000000.0));

    return diff_time;
}

/**
 * Print message timestamp
 */
static int
_LSMonitorPrintTime(const struct timespec *time)
{
    return fprintf(stdout, "%.3f", ((double)(time->tv_sec)) + (((double)time->tv_nsec) / (double)1000000000.0));
}

/**
 * Print monitor message type
 */
static int
_LSMonitorPrintType(const _LSMonitorMessageType message_type)
{
    switch (message_type)
    {
    case _LSMonitorMessageTypeTx:
        return fprintf(stdout, " TX  ");
    case _LSMonitorMessageTypeRx:
        return fprintf(stdout, " RX ");
    default:
        LOG_LS_ERROR(MSGID_LS_UNKNOWN_MSG, 1, PMLOGKFV("TYPE", "%d", message_type), "Unknown monitor message type");
        return fprintf(stdout, " UN ");
    }
}

static gboolean
_LSMonitorIdleHandler(gpointer data)
{
    _LSMonitorQueue *queue = static_cast<_LSMonitorQueue *>(data);
    _LSMonitorQueuePrint(queue, 1000, dup_hash_table, debug_output);
    return TRUE;
}

void
_LSMonitorMessagePrint(_LSTransportMessage *message)
{
    if (LSTransportMessageFilterMatch(message, message_filter_str))
    {
        const _LSMonitorMessageData *message_data = _LSTransportMessageGetMonitorMessageData(message);

        if (json_output)
        {
            json_formatter->PrintMessage(message);
        }
        else if (compact_output)
        {
            unsigned int nchar = _LSMonitorPrintTime(&message_data->timestamp);
            nchar += _LSMonitorPrintType(message_data->type);

            int mchar = LSTransportMessagePrintCompactHeader(message, stdout);
            if (mchar > 0)
            {
                nchar += mchar;
                if (two_line_output)
                {
#define _PAYLOAD_LEFT_PADDING 14
                    fprintf(stdout, "\n%*s", _PAYLOAD_LEFT_PADDING, " ");
                    nchar = _PAYLOAD_LEFT_PADDING;
                }
                else
                {
                    nchar += fprintf(stdout, " ");
                }

                /* In case length of header exceed terminal_width, use one more line */
                while (terminal_width < nchar)
                {
                    nchar -= terminal_width;
                }

                LSTransportMessagePrintCompactPayload(message, stdout, terminal_width - nchar - 1);
                fprintf(stdout, "\n");
            }
        }
        else
        {
            _LSMonitorPrintTime(&message_data->timestamp);
            _LSMonitorPrintType(message_data->type);
            LSTransportMessagePrint(message, stdout);
        }
        fflush(stdout);
    }
}

static LSMessageHandlerResult
_LSMonitorMessageHandler(_LSTransportMessage *message, void *context)
{
    if (sort_by_timestamps)
    {
        _LSMonitorMessagePrint(message);
    }
    else
    {
        /* Queue up messages */
        _LSMonitorQueueMessage(queue, message);
    }

    return LSMessageHandlerResultHandled;
}

static void
_PrintMonitorListInfo(const GSList *info_list)
{
    for (; info_list != NULL; info_list = g_slist_next(info_list))
    {
        const _LSMonitorListInfo *cur = static_cast<const _LSMonitorListInfo *>(info_list->data);
        fprintf(stdout, "%-10d\t%-30s\t%-35s\t%-20s\t%-20s\n",
                cur->pid, cur->service_name, cur->exe_path, cur->service_type, cur->unique_name);
    }
}

static void
_FreeMonitorListInfoItem(_LSMonitorListInfo *info)
{
    LS_ASSERT(info != NULL);
    g_free(info->unique_name);
    g_free(info->service_name);
    g_free(info->exe_path);
    g_free(info->service_type);
    g_free(info);
}

static void
_FreeMonitorListInfo(GSList **list)
{
    for (; *list != NULL; *list = g_slist_next(*list))
    {
        _LSMonitorListInfo *info = static_cast<_LSMonitorListInfo *>((*list)->data);
        if (info) _FreeMonitorListInfoItem(info);
        *list = g_slist_delete_link(*list, *list);
    }
}

static bool
_CanGetSubscriptionInfo(_LSMonitorListInfo *info)
{
    /* Needs to have a valid service name and be dynamic
     * or static (i.e., not a client)
     */
    if (info->service_name && ((g_strcmp0(info->service_type, DYNAMIC_SERVICE_STR) == 0)
                           || (g_strcmp0(info->service_type, STATIC_SERVICE_STR) == 0)))
    {
        return true;
    }
    return false;
}

static void
_PrintSubscriptionResultsList(GSList *sub_list)
{
    for (; sub_list != NULL; sub_list = g_slist_next(sub_list))
    {
        LSMessage *msg = static_cast<LSMessage *>(sub_list->data);

        /* We may get error messages if the service goes down between the
         * time we find out about it and send the subscription info request */
        if (!LSMessageIsHubErrorMessage(msg))
        {
            const char *sub_text = LSMessageGetPayload(msg);
            const char *service = LSMessageGetSenderServiceName(msg);
            fprintf(stdout, "%s: %s\n", service, sub_text);
        }

        LSMessageUnref(msg);
    }
    fprintf(stdout, "\n");
    fflush(stdout);
}

static void
_PrintSubscriptionResults()
{
    fprintf(stdout, list_subscriptions ? "SUBSCRIPTIONS:\n" : "BUS MALLOC DATA:\n");
    _PrintSubscriptionResultsList(sub_replies);
}

static bool
_SubscriptionResultsCallback(LSHandle *sh, LSMessage *reply, void *ctx)
{
    static int received_replies = 0;
    _SubscriptionReplyData *reply_data = static_cast<_SubscriptionReplyData *>(ctx);

    LSMessageRef(reply);
    (*reply_data->reply_list) = g_slist_prepend((*reply_data->reply_list), reply);

    received_replies++;

    if (received_replies == reply_data->total_replies)
    {
        _PrintSubscriptionResults();

        g_slist_free(sub_replies);

        g_free(reply_data);

        /* done */
        g_main_loop_quit(mainloop);
    }


    return true;
}

static void
_ListServiceSubscriptions(LSHandle *sh, LSFilterFunc callback, GSList *monitor_list, int total_services,
                          GSList **reply_list)
{
    LSError lserror;
    LSErrorInit(&lserror);

    bool retVal = false;

    _SubscriptionReplyData *data = static_cast<_SubscriptionReplyData *>(g_malloc(sizeof(_SubscriptionReplyData)));

    /* NOTE: we only allocate one of these items and pass it as the data to all the callbacks */
    data->reply_list = reply_list;
    data->total_replies = total_services;

    for (; monitor_list != NULL; monitor_list = g_slist_next(monitor_list))
    {
        _LSMonitorListInfo *cur = static_cast<_LSMonitorListInfo *>(monitor_list->data);

        /* skip any non-services and the monitor itself */
        if (!_CanGetSubscriptionInfo(cur))
        {
            continue;
        }

        char *uri = g_strconcat("luna://", cur->service_name, list_subscriptions ? SUBSCRIPTION_DEBUG_METHOD : MALLOC_DEBUG_METHOD, NULL);

        retVal = LSCall(sh, uri, "{}", callback, data, NULL, &lserror);
        if (!retVal)
        {
            LSErrorPrint(&lserror, stderr);
            LSErrorFree(&lserror);
        }
        g_free(uri);
    }
}

static void
_DisconnectCustomTransport()
{
    static bool is_disconnected = false;

    if (!is_disconnected)
    {
        _LSTransportDisconnect(transport, true);
        _LSTransportDeinit(transport);
        is_disconnected = true;
    }
}

static LSMessageHandlerResult
_LSMonitorListMessageHandler(_LSTransportMessage *message, void *context)
{
    LS_ASSERT(_LSTransportMessageGetType(message) == _LSTransportMessageTypeListClientsReply);

    const char *unique_name = NULL;
    const char *service_name = NULL;
    int32_t pid = 0;
    const char *exe_path = NULL;
    const char *service_type = NULL;
    static int total_sub_services = 0;

    static GSList *monitor_info = NULL;

    _LSTransportMessageIter iter;
    _LSTransportMessageIterInit(message, &iter);

    while (_LSTransportMessageIterHasNext(&iter))
    {
        _LSMonitorListInfo *info = static_cast<_LSMonitorListInfo *>(g_malloc(sizeof(_LSMonitorListInfo)));

        if (!_LSTransportMessageGetString(&iter, &unique_name)) break;
        info->unique_name = g_strdup(unique_name);
        _LSTransportMessageIterNext(&iter);

        if (!_LSTransportMessageGetString(&iter, &service_name)) break;
        info->service_name = g_strdup(service_name);
        _LSTransportMessageIterNext(&iter);

        if (!_LSTransportMessageGetInt32(&iter, &pid)) break;
        info->pid = pid;
        _LSTransportMessageIterNext(&iter);

        if (!_LSTransportMessageGetString(&iter, &exe_path)) break;
        info->exe_path = g_strdup(exe_path);
        _LSTransportMessageIterNext(&iter);

        if (!_LSTransportMessageGetString(&iter, &service_type)) break;
        info->service_type = g_strdup(service_type);
        _LSTransportMessageIterNext(&iter);

        if (_CanGetSubscriptionInfo(info))
        {
            total_sub_services++;
        }

        monitor_info = g_slist_prepend(monitor_info, info);
    }

    /* Process and display when we receive responses */
    if (list_subscriptions || list_malloc)
    {
        LSError lserror;
        LSErrorInit(&lserror);

        LSHandle *sh = NULL;

        _DisconnectCustomTransport();

        if (total_sub_services == 0)
        {
            _PrintSubscriptionResults();
            g_main_loop_quit(mainloop);
            return LSMessageHandlerResultHandled;
        }

        /* register as a "high-level" client */
        if (!LSRegister(ls_monitor_service_name.c_str(), &sh, &lserror))
        {
            LSErrorPrint(&lserror, stderr);
            LSErrorFree(&lserror);
        }
        else
        {
            LSGmainAttach(sh, mainloop, &lserror);
            _ListServiceSubscriptions(sh, _SubscriptionResultsCallback, monitor_info, total_sub_services, &sub_replies);
        }
    }

    if (list_clients)
    {
        fprintf(stdout, "HUB CLIENTS:\n");
        fprintf(stdout, "%-10s\t%-30s\t%-35s\t%-20s\t%-20s\n", "PID", "SERVICE NAME", "EXE", "TYPE", "UNIQUE NAME");
        _PrintMonitorListInfo(monitor_info);
        fprintf(stdout, "\n");
        _FreeMonitorListInfo(&monitor_info);

        g_main_loop_quit(mainloop);
    }
    return LSMessageHandlerResultHandled;
}

static LSMessageHandlerResult
_LSMonitorMethodListMessageHandler(_LSTransportMessage *message, void *)
{
    LS_ASSERT(_LSTransportMessageGetType(message) == _LSTransportMessageTypeReply);

    JSchemaInfo schemaInfo;

    // TO-DO: Validate against service.schema when
    // local resolver will be available.
    jschema_info_init(&schemaInfo, jschema_all(), NULL, NULL);
    jvalue_ref params = jdom_parse(j_cstr_to_buffer(_LSTransportMessageGetPayload(message)),
                                   DOMOPT_NOOPT, &schemaInfo);

    bool succeeded = false;
    jboolean_get(jobject_get(params, J_CSTR_TO_BUF("returnValue")), &succeeded);

    if (!succeeded)
    {
        fprintf(stdout, "Client returned error instead of methods list: %s.\n",
                jvalue_tostring_simple(jobject_get(params, J_CSTR_TO_BUF("errorText"))));
    }
    else
    {
        fprintf(stdout, "\nMETHODS AND SIGNALS REGISTERED BY SERVICE '%s' WITH UNIQUE NAME '%s' AT HUB\n\n",
                _LSTransportMessageGetSenderServiceName(message),
                _LSTransportMessageGetSenderUniqueName(message));

        jobject_iter cat_iterator, meth_iterator;
        jobject_key_value category, method;
        jobject_iter_init(&cat_iterator, jobject_get(params, J_CSTR_TO_BUF("categories")));
        while (jobject_iter_next(&cat_iterator, &category))
        {
            fprintf(stdout, "%*s\%s:\n", 2, "", jvalue_tostring_simple(category.key));

            jobject_iter_init(&meth_iterator, jobject_get(category.value, J_CSTR_TO_BUF("methods")));
            while (jobject_iter_next(&meth_iterator, &method))
            {
                fprintf(stdout, "%*s\%s: %s\n", 6, "", jvalue_tostring_simple(method.key), jvalue_tostring_simple(method.value));
            }
        }
    }

    g_main_loop_quit(mainloop);

    return LSMessageHandlerResultHandled;
}

static LSMessageHandlerResult
_LSMonitorAPIVersionMessageHandler(_LSTransportMessage *message, void *)
{
    LS_ASSERT(_LSTransportMessageGetType(message) == _LSTransportMessageTypeReply);

    using namespace pbnjson;

    do
    {
        JValue params = JDomParser::fromString(_LSTransportMessageGetPayload(message));
        if (!params.isValid())
        {
            fprintf(stderr, "Internal error. Invalid API version reply from the hub: %s\n",
                    _LSTransportMessageGetPayload(message));
            exit_code = 1;
            break;
        }

        if (!params["returnValue"].asBool())
        {
            fprintf(stderr, "Unknown service: %s\n", params["unknown"][0].stringify().c_str());
            exit_code = 1;
            break;
        }

        JValue versions = params["versions"];
        for (auto service : versions.children())
        {
            fprintf(stdout, "%s %s\n",
                    service.first.asString().c_str(),
                    service.second.asString().c_str());
        }
    } while (false);

    g_main_loop_quit(mainloop);

    return LSMessageHandlerResultHandled;
}

static LSMessageHandlerResult
_LSMonitorDumpHubDataHandler(_LSTransportMessage *message, void *)
{
    // The hub will send the dump in text chunks, ending with the empty
    // last chunk. The format is asumed to be simple CSV text lines
    // to be easily processible with standard unix tools like grep, sed, awk.
    LS_ASSERT(_LSTransportMessageGetType(message) == _LSTransportMessageTypeDumpHubDataReply);

    _LSTransportMessageIter iter;
    _LSTransportMessageIterInit(message, &iter);

    bool last_message = true;
    const char *line = nullptr;
    while (_LSTransportMessageGetString(&iter, &line))
    {
        std::cout << line;
        last_message = false;

        _LSTransportMessageIterNext(&iter);
    }

    if (last_message)
        g_main_loop_quit(mainloop);

    return LSMessageHandlerResultHandled;
}

void
_LSMonitorMethodListFailureHandler(_LSTransportMessage *message, _LSTransportMessageFailureType failure_type, void *)
{
    switch (failure_type)
    {
    case _LSTransportMessageFailureTypeServiceNotExist:
        fprintf(stdout, "Service '%s' is not registered at hub\n",
                list_servicename_methods);
        break;
    case _LSTransportMessageFailureTypeServiceUnavailable:
        fprintf(stdout, "Service '%s' currently is not available at hub\n",
                list_servicename_methods);
        break;
    default:
        fprintf(stdout, "Recieved error from hub for service '%s': %d\n",
                list_servicename_methods, failure_type);
    }

    g_main_loop_quit(mainloop);
}

static void
_HandleShutdown(int signal)
{
    g_main_loop_quit(mainloop);
}

static void
_HandleCommandline(int argc, char *argv[])
{
    GError *gerror = NULL;
    GOptionContext *opt_context = NULL;

    /* handle commandline args */
    static GOptionEntry opt_entries[] =
    {
        {"filter", 'f', 0, G_OPTION_ARG_STRING, &message_filter_str, "Filter by service name (or unique name)", "com.palm.foo"},
        {"list", 'l', 0, G_OPTION_ARG_NONE, &list_clients, "List all entities connected to the hub", NULL},
        {"subscriptions", 's', 0, G_OPTION_ARG_NONE, &list_subscriptions, "List all subscriptions in the system", NULL},
        {"introspection", 'i', 0, G_OPTION_ARG_STRING, &list_servicename_methods, "List service methods and signals", "com.palm.foo"},
        {"api-version", 'v', 0, G_OPTION_ARG_STRING, &get_servicename_api_version, "Get service API version", "com.palm.foo"},
        {"malloc", 'm', 0, G_OPTION_ARG_NONE, &list_malloc, "List malloc data from all services in the system", NULL},
        {"debug", 'd', 0, G_OPTION_ARG_NONE, &debug_output, "Print extra output for debugging monitor but with UNBOUNDED MEMORY GROWTH", NULL},
        {"compact", 'c', 0, G_OPTION_ARG_NONE, &compact_output, "Print compact output to fit terminal. Take precedence over debug", NULL},
        {"json", 'j', 0, G_OPTION_ARG_NONE, &json_output, "Print JSON formatted output for easier parsing. Take precedence over debug", NULL},
        {"sort-by-timestamps", 't', 0, G_OPTION_ARG_NONE, &sort_by_timestamps, "Sort output by timestamps instead of serials", NULL},
        {"dump-hub-data-csv", 0, 0, G_OPTION_ARG_NONE, &dump_hub_data, "Dump hub data in CSV format", NULL},
        { NULL }
    };

    opt_context = g_option_context_new("- Luna Service monitor");
    g_option_context_add_main_entries(opt_context, opt_entries, NULL);
    g_option_context_set_description(opt_context, ""
"Compact mode symbols:\n"
"   >*      signal\n"
"   >|      cancel method call\n"
"    >      method call\n"
"   <       reply");

    if (!g_option_context_parse(opt_context, &argc, &argv, &gerror))
    {
        g_critical("Error processing commandline args: %s", gerror->message);
        g_error_free(gerror);
        exit(EXIT_FAILURE);
    }

    g_option_context_free(opt_context);

#ifndef INTROSPECTION_DEBUG
    if (list_servicename_methods)
    {
        g_message("Library is built without introspection support, please rebuild with INTROSPECTION_DEBUG.");
        exit(EXIT_FAILURE);
    }
#endif

    if (compact_output)
    {
        debug_output = false;
    }

    if (debug_output)
    {
        g_warning("extra output for debugging monitor enabled, causes UNBOUNDED MEMORY GROWTH");
    }
}

static void
_HandleTerminal()
{
#ifdef TIOCGWINSZ
    struct winsize w;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);

    if (w.ws_col > TERMINAL_WIDTH_DEFAULT)
    {
        terminal_width = w.ws_col;
    }
#endif
    two_line_output = terminal_width < TERMINAL_WIDTH_WIDE;
}

#ifdef SIGWINCH
static void
_HandleWindowChange(int signal)
{
    terminal_width = TERMINAL_WIDTH_DEFAULT;
    _HandleTerminal();
}
#endif

void _error(LSError &lserror)
{
    LSErrorPrint(&lserror, stderr);
    LSErrorFree(&lserror);
    exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
    LSError lserror;
    LSErrorInit(&lserror);

    mainloop = g_main_loop_new(NULL, FALSE);

    /* send message to hub to let clients know that they should start
     * sending us their messages */

    LSTransportHandlers handler =
    {
        .message_failure_handler = NULL,
        .message_failure_context = NULL,
        .disconnect_handler = NULL,
        .disconnect_context = NULL,
        .msg_handler = _LSMonitorMessageHandler,
        .msg_context = NULL,
    };

    _LSTransportSetupSignalHandler(SIGTERM, _HandleShutdown);
    _LSTransportSetupSignalHandler(SIGINT, _HandleShutdown);
#ifdef SIGWINCH
    _LSTransportSetupSignalHandler(SIGWINCH, _HandleWindowChange);
#endif
    _HandleCommandline(argc, argv);
    _HandleTerminal();

    if (list_clients || list_servicename_methods || get_servicename_api_version || dump_hub_data)
    {
        ls_monitor_service_name += std::to_string(getpid());
    }
    // otherwise we use a single name and thus only one instance will be able to start

    if (list_clients || list_subscriptions || list_malloc)
    {
        handler.msg_handler = _LSMonitorListMessageHandler;
    }
    else if (list_servicename_methods)
    {
        handler.msg_handler = _LSMonitorMethodListMessageHandler;
        handler.message_failure_handler = _LSMonitorMethodListFailureHandler;
    }
    else if (get_servicename_api_version)
    {
        handler.msg_handler = _LSMonitorAPIVersionMessageHandler;
    }
    else if (dump_hub_data)
    {
        handler.msg_handler = _LSMonitorDumpHubDataHandler;
    }

    if (!_LSTransportInit(&transport, ls_monitor_service_name.c_str(), nullptr, &handler, &lserror))
    {
        _error(lserror);
    }

    if (!_LSTransportConnect(transport, &lserror))
    {
        _error(lserror);
    }

    if (!_LSTransportNodeUp(transport, false, &lserror))
    {
        _error(lserror);
    }

    _LSTransportGmainAttach(transport, g_main_loop_get_context(mainloop));

    /* message printing callback */
    //g_idle_add(_LSMonitorIdleHandlerPrivate, NULL);
    queue = _LSMonitorQueueNew();
    g_timeout_add(500, _LSMonitorIdleHandler, queue);

    if (dump_hub_data)
    {
        if (!_LSTransportSendMessageDumpHubData(transport, &lserror))
        {
            _error(lserror);
        }
    }
    else if (get_servicename_api_version)
    {
        auto params = pbnjson::JObject{{"services", pbnjson::JArray{get_servicename_api_version}}};
        auto payload = params.stringify();

        LSMessageToken token;
        if (!LSTransportSendMethodToHub(transport, "getServiceAPIVersions",
                                        payload.c_str(), &token, &lserror))
        {
            _error(lserror);
        }
    }
    else if (list_servicename_methods)
    {
        if (!_LSTransportSendMessageListServiceMethods(transport, list_servicename_methods, false, &lserror))
        {
            _error(lserror);
        }
    }
    else if (list_clients || list_subscriptions || list_malloc)
    {
        if (!_LSTransportSendMessageListClients(transport, &lserror))
        {
            _error(lserror);
        }
    }
    else
    {
        /* send the message to the hub to tell clients to connect to us */

        if (!LSTransportSendMessageMonitorRequest(transport, &lserror))
        {
            _error(lserror);
        }

        if (json_output)
        {
            json_formatter = std::unique_ptr<JsonOutputFormatter>(new JsonOutputFormatter(stdout));
        }
        else if (debug_output)
        {
            fprintf(stdout, "Debug\t\tTime\tStatus\tProt\tType\tSerial\t\tSender\t\tDestination\t\tMethod                            \tPayload\n");
        }
        else if (compact_output)
        {
            fprintf(stdout, "Time \tStatus Prot&Type Caller.Serial Callee/Method Payload\n");
        }
        else
        {
            fprintf(stdout, "Time\tStatus\tProt\tType\tSerial\t\tSender\t\tDestination\t\tMethod                            \tPayload\n");
        }
        fflush(stdout);
    }

    dup_hash_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

    g_main_loop_run(mainloop);
    g_main_loop_unref(mainloop);

    _DisconnectCustomTransport();

    g_hash_table_destroy(dup_hash_table);

    return exit_code;
}
