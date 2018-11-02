// Copyright (c) 2015-2019 LG Electronics, Inc.
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

#ifndef _LOG_IDS_H
#define _LOG_IDS_H

/* HUB */
#define MSGID_LSHUB_DIR_OPEN_ERROR              "LSHUB_DIR_OPEN_ERROR"  /** Failed to open directory */
#define MSGID_LSHUB_MANIFEST_FILE_ERROR         "LSHUB_MANIFEST_FILE_ERROR"   /** Manifest file error */
#define MSGID_LSHUB_ACTIVE_PERMS_EXIST          "LSHUB_ACT_PERMS_EXIST" /** Active permissions exist for registered service */
#define MSGID_LSHUB_ALREADY_RUNNING             "LSHUB_ALRDY_RUN"       /** An instance of the %s hub is already running */
#define MSGID_LSHUB_ARGUMENT_ERR                "LSHUB_ARG"             /** Error in hub program arguments */
#define MSGID_LSHUB_BAD_PARAMS                  "LSHUB_BAD_PARAMS"      /** Unknown or wrong argument for function call */
#define MSGID_LSHUB_CANT_PUSH_ROLE              "LSHUB_PUSH_ROLE"       /** Unable to push role */
#define MSGID_LSHUB_CLIENT_ERROR                "LSHUB_CLIENT_ERROR"    /** Hub client error */
#define MSGID_LSHUB_CONF_FILE_ERROR             "LSHUB_CONF"            /** Mandatory configuration file not provided */
#define MSGID_LSHUB_CONTAINERS_FILE_ERR         "LSHUB_CONTAINERS_FILE" /** Error in container applications file */
#define MSGID_LSHUB_DATA_ERROR                  "LSHUB_DATA"            /** Error in hub data structures */
#define MSGID_LSHUB_GROUP_FILE_ERR              "LSHUB_GROUP_FILE"      /** Error in group file */
#define MSGID_LSHUB_DEVMODE                     "LSHUB_DEVMODE"         /** Devmode message */
#define MSGID_LSHUB_DEVMODE_ERR                 "LSHUB_DEVMODE_ERR"     /** Error in devmode certificate file */
#define MSGID_LSHUB_INOTIFY_ERR                 "LSHUB_INOTIFY"         /** Inotify err */
#define MSGID_LSHUB_INVALID_CONN_STATE          "LSHUB_INV_CONN_STATE"  /** Invalid connect state */
#define MSGID_LSHUB_INVALID_STATE               "LSHUB_INVAL_STATE"     /** Invalid state */
#define MSGID_LSHUB_KEYFILE_ERR                 "LSHUB_KEYFILE"         /** Error in config keyfile */
#define MSGID_LSHUB_MEMORY_ERR                  "LSHUB_MEM"             /** Hub internal memory managment error*/
#define MSGID_LSHUB_MKDIR_ERROR                 "LSHUB_MKDIR"           /** Unable to create directory */
#define MSGID_LSHUB_NO_CLIENT                   "LSHUB_NO_CLIENT"       /** Unable to get client from message */
#define MSGID_LSHUB_NO_CONTAINERS_DIR           "LSHUB_NO_CONT_DIR"     /** Can not open containers directory */
#define MSGID_LSHUB_NO_DYNAMIC_SERVICE          "LSHUB_NO_DYN_SRVS"     /** Service not found in dynamic service set */
#define MSGID_LSHUB_NO_EXE_PATH                 "LSHUB_NO_EXE_PATH"     /** No executable path for connected client */
#define MSGID_LSHUB_NO_FD                       "LSHUB_NO_FD"           /** Unable to find fd */
#define MSGID_LSHUB_NO_INBOUND_PERMS            "LSHUB_NO_INB_PERMS"    /** Permissions does not allow inbound */
#define MSGID_LSHUB_NO_MONITOR                  "LSHUB_NO_MONITOR"      /** Unable to find monitor in connected client map */
#define MSGID_LSHUB_NO_MONITOR_MESSAGE          "LSHUB_NO_MON_MSG"      /** Monitor message not sent by monitor */
#define MSGID_LSHUB_NO_OUTBOUND_PERMS           "LSHUB_NO_OUT_PERMS"    /** Permissions does not allow outbound */
#define MSGID_LSHUB_NO_PERMISSION_FOR_NAME      "LSHUB_NO_NAME_PERMS"   /** Executable does not have permission to register name */
#define MSGID_LSHUB_NO_PERMS_FOR_SERVICE        "LSHUB_NO_SERV_PERMS"   /** No permissions configured for service */
#define MSGID_LSHUB_NO_ROLE_FILE                "LSHUB_NO_ROLE_FILE"    /** No role file for executable */
#define MSGID_LSHUB_NO_ROLE_PATH                "LSHUB_NO_ROLE_PATH"    /** Unable to get role path (sender service name */
#define MSGID_LSHUB_NO_SERVICE                  "LSHUB_NO_SERVICE"      /** Failed to get service name for message */
#define MSGID_LSHUB_NO_SIGNAL_PERMS             "LSHUB_NO_SIGNAL_PERMS" /** Not allowed to send signals */
#define MSGID_LSHUB_PENDING_CONNECT_ERR         "LSHUB_PNDING_CONN_ERR" /** Failed to connect to the pending client */
#define MSGID_LSHUB_PERMISSION_FILE_ERR         "LSHUB_PERMISSION_FILE" /** Error in permissions file */
#define MSGID_LSHUB_PIPE_ERR                    "LSHUB_PIPE"            /** Pipe error */
#define MSGID_LSHUB_PUSH_ROLE_ERR               "LSHUB_PUSH_ROLE"       /** Error due role pushing */
#define MSGID_LSHUB_REG_REPLY_ERR               "LSHUB_REG_REPLY"       /** error sending signal registration reply */
#define MSGID_LSHUB_ROLE_EXISTS                 "LSHUB_ROLE_EXISTS"     /** Role already exists for exe_path */
#define MSGID_LSHUB_ROLE_DEPRECATED             "LSHUB_ROLE_DEPRECATED" /** Deprecated ls2 permission model is used */
#define MSGID_LSHUB_ROLE_FILE_ERR               "LSHUB_ROLE_FILE"       /** Error in role file */
#define MSGID_LSHUB_SENDMSG_ERROR               "LSHUB_SENDMSG"         /** Message sending error */
#define MSGID_LSHUB_SERVICE_ADD_ERR             "LSHUB_SRV_ADD_ERROR"   /** Error adding service */
#define MSGID_LSHUB_SERVICE_CONNECT_ERROR       "LSHUB_SRV_CONN"        /** Could not connect to service */
#define MSGID_LSHUB_SERVICE_EXISTS              "LSHUB_SERVICE_EXISTS"  /** Servicename already exists for exe_path */
#define MSGID_LSHUB_SERVICE_FILE_ERR            "LSHUB_SRV_FILE"        /** Error in service file */
#define MSGID_LSHUB_SERVICE_LAUNCH_ERR          "LSHUB_SRV_LNCH"        /** Error launching service */
#define MSGID_LSHUB_SERVICE_NOT_LISTED          "LSHUB_NOT_LSTED"       /** Service not listed in service files */
#define MSGID_LSHUB_STATE_MAP_ERR               "LSHUB_STATE_MAP"       /** Error in service state map */
#define MSGID_LSHUB_SERV_NAME_REGISTERED        "LSHUB_SRV_NAME_RGSTRD" /** Service is already registered */
#define MSGID_LSHUB_SERV_RUNNING                "LSHUB_SERV_RUNNING"    /** Service is already running */
#define MSGID_LSHUB_SIGNAL_ERR                  "LSHUB_SIGNAL"          /** Signal error */
#define MSGID_LSHUB_SOCKOPT_ERR                 "LSHUB_SOCKOPT"         /** Getsockopt failed for fd */
#define MSGID_LSHUB_SOCK_ERR                    "LSHUB_SOCK"            /** Error removing socket */
#define MSGID_LSHUB_SPAWN_ERR                   "LSHUB_SPAWN"           /** Error attemtping to launch service */
#define MSGID_LSHUB_TIMER_ERR                   "LSHUB_TMR"             /** Error due timer setting */
#define MSGID_LSHUB_UNABLE_TO_START_DAEMON      "LSHUB_DAEMON"          /** Unable to become a daemon */
#define MSGID_LSHUB_UNAME_ERROR                 "LSHUB_UNAME"           /** Unique name error */
#define MSGID_LSHUB_UNKNOWN_DISCONNECT_MESSAGE  "LSHUB_UNK_DISC_MSG"    /** Received a disconnect message for client */
#define MSGID_LSHUB_UNKNOWN_GROUP               "LSHUB_UNK_GROUP"       /** Found unknown group */
#define MSGID_LSHUB_UPSTART_ERROR               "LSHUB_UPSTART"         /** Unable to emit upstart event */
#define MSGID_LSHUB_VERSION_PARSE_ERROR         "LSHUB_VERSION_PARSE"   /** Error in parsing version string */
#define MSGID_LSHUB_WATCHDOG_ERR                "LSHUB_WD"              /** Watchdog errors */
#define MSGID_LSHUB_WRONG_PROTOCOL              "LSHUB_BAD_PROTOCOL"    /** Transport protocol mismatch */
#define MSGID_LSHUB_OOM_ERR                     "LSHUB_MEM"             /** Out of memory error */
#define MSGID_LSHUB_ANONYMOUS_CLIENT            "LSHUB_ANON_CLI"        /** Deprecated quirks for anonymous clients */
#define MSGID_LSHUB_JSON_ERR                    "LSHUB_JSON_ERR"        /** Hub got an error during parsing JSON */
#define MSGID_LSHUB_JSON_READ_ERR               "LSHUB_JSON_READ_ERR"   /** Fail to open/read/mmap JSON file */

/* LUNA SERVICE */
#define MSGID_LS_ACCESS_ERR                     "LS_ACCESS"             /** Message access error */
#define MSGID_LS_ALREADY_SHUTDOWND              "LS_ALRDY_SHDND"        /** already sent shut down message */
#define MSGID_LS_ASSERT                         "LS_ASSERT"             /** LS internal assert */
#define MSGID_LS_CANT_PING                      "LS_CANT_PING"          /** Sending ping failed */
#define MSGID_LS_CANT_CANCEL_METH               "LS_CANC_METH"          /** Can't cancel method */
#define MSGID_LS_CATALOG_ERR                    "LS_CATALOG_REG"        /** Error in subscription catalog */
#define MSGID_LS_CATEGORY_REGISTERED            "LS_CATEG_REG"          /** Category is already registered */
#define MSGID_LS_CHANNEL_ERR                    "LS_CHAN"               /** Channel error */
#define MSGID_LS_CLOCK_ERROR                    "LS_CLOCK"              /** Monotonic clock error */
#define MSGID_LS_CONN_ERROR                     "LS_CONN"               /** Failed to connect */
#define MSGID_LS_DEPRECATED                     "LS_DEPRECATED"         /** Deprecated function */
#define MSGID_LS_DUP_ERR                        "LS_DUP"                /** FD Duplication error */
#define MSGID_LS_EAGAIN_ERR                     "LS_EAGAIN"             /** Resource temporarily unavailable */
#define MSGID_LS_ERROR_INIT_ERR                 "LS_ERR_INIT"           /** LSError is already initialized */
#define MSGID_LS_INTROS_SEND_FAILED             "LS_INTROS_SEND_FAIL"   /** Sending introspection data failed */
#define MSGID_LS_INVALID_BUS                    "LS_BUS"                /** Replying on different bus */
#define MSGID_LS_INVALID_CALL                   "LS_INVALID_CALL"       /** Unsupported call type */
#define MSGID_LS_INVALID_HANDLE                 "LS_INVALID_HANDLE"     /** Invalid handle */
#define MSGID_LS_INVALID_JSON                   "LS_INVAL_JSON"         /** Invalid json */
#define MSGID_LS_INVALID_PAYLOAD                "LS_INVALID_PAYLOAD"    /** Invalid payload */
#define MSGID_LS_INVALID_URI                    "LS_INVALID_URI"        /** Not a valid uri */
#define MSGID_LS_INVALID_URI_METHOD             "LS_INV_URI_METH"       /** Invalid method in URI */
#define MSGID_LS_INVALID_URI_PATH               "LS_INV_URI_PATH"       /** Invalid path in URI */
#define MSGID_LS_INVALID_URI_SERVICE_NAME       "LS_INV_URI_SNAME"      /** Invalid service name in URI */
#define MSGID_LS_LOCK_FILE_ERR                  "LS_LCK_FILE"           /** Lock file error */
#define MSGID_LS_MAGIC_ASSERT                   "LS_MAGIC_ASSERT"       /** No LS_MAGIC field */
#define MSGID_LS_MAINCONTEXT_ERROR              "LS_MCTXT"              /** Maincontext error */
#define MSGID_LS_MAINLOOP_ERROR                 "LS_MLOOP"              /** Mainloop error */
#define MSGID_LS_MALLOC_SEND_FAILED             "LS_MALL_SEND_FAIL"     /** Sending malloc info failed */
#define MSGID_LS_MALLOC_TRIM_SEND_FAILED        "LS_MALLTRIM_SEND_FAIL" /** Sending malloc trim result failed */
#define MSGID_LS_MSG_ERR                        "LS_MSG"                /** Messages errors */
#define MSGID_LS_MSG_NOT_HANDLED                "LS_MSG_NOT_HNDLD"      /** Messages not handled */
#define MSGID_LS_MUTEX_ERR                      "LS_MUTEX"              /** Mutex error */
#define MSGID_LS_NOT_AN_ERROR                   "LS_NOT_AN"             /** The message type is not an error type */
#define MSGID_LS_NOT_IMPLEMENTED                "LS_NOT_IMPLEMENTED"    /** Feature is not implemented */
#define MSGID_LS_NO_CALLBACK                    "LS_NO_CALLBACK"        /** No callback specified */
#define MSGID_LS_NO_CATEGORY                    "LS_NO_CATEGORY"        /** Couldn't find category */
#define MSGID_LS_NO_CATEGORY_TABLE              "LS_NO_CATEGORY_TABLE"  /** No category table for handler */
#define MSGID_LS_NO_METHOD                      "LS_NO_METH"            /** Couldn't find method */
#define MSGID_LS_NO_TOKEN                       "LS_NO_TOKEN"           /** No token in callmap */
#define MSGID_LS_NULL_CLIENT                    "LS_NULL_CLIENT"        /** Client without client info */
#define MSGID_LS_NULL_LS_ERROR                  "LS_NULL_LS_ERROR"      /** Null lserror in log function */
#define MSGID_LS_OOM_ERR                        "LS_MEM"                /** Out of memory error */
#define MSGID_LS_PARAMETER_IS_NULL              "LS_PARAM"              /** Parameter == NULL */
#define MSGID_LS_PID_PATH_ERR                   "LS_PID_PATH"           /** Can't get executable for pid */
#define MSGID_LS_PID_READ_ERR                   "LS_PID_READ"           /** Can't read PID from file */
#define MSGID_LS_PIPE_ERR                       "LS_PIPE"               /** Pipe error */
#define MSGID_LS_PRIVILEDGES_ERROR              "LS_PRIV"               /** Not enaugh privileges */
#define MSGID_LS_QNAME_ERR                      "LS_QNAME"              /** Query name error */
#define MSGID_LS_QUEUE_ERROR                    "LS_QUEUE"              /** Message queue error */
#define MSGID_LS_REPLY_TOK                      "LS_REPLY_TOK"          /** Getting reply token for message type */
#define MSGID_LS_REQUEST_NAME                   "LS_REQ_NAME"           /** Error during name request */
#define MSGID_LS_SEND_ERROR                     "LS_SEND"               /** Sending error */
#define MSGID_LS_SERIAL_ERROR                   "LS_SERIAL"             /** Serial map error */
#define MSGID_LS_SHARED_MEMORY_ERR              "LS_SHM"                /** Shared memory error*/
#define MSGID_LS_SIGNAL_NOT_REGISTERED          "LS_SIG_NREG"           /** Signal not registered */
#define MSGID_LS_SOCK_ERROR                     "LS_SOCK"               /** Socket error */
#define MSGID_LS_SUBSCRIPTION_ERR               "LS_SUBS"               /** Subscription error */
#define MSGID_LS_SUBSEND_FAILED                 "LS_SUB_SEND_FAIL"      /** Sending subscription info failed */
#define MSGID_LS_TIMER_NO_CALLBACK              "LS_TIMER_NO_CBCK"      /** Timeout source dispatched without callback */
#define MSGID_LS_TIMER_NO_CONTEXT               "LS_TIMER_NO_CTX"       /** Cannot get context for timer_source */
#define MSGID_LS_TOKEN_ERR                      "LS_TOK_INV"            /** Token error */
#define MSGID_LS_TRANSPORT_INIT_ERR             "LS_TRANS_INIT"         /** Error during transport creation */
#define MSGID_LS_TRANSPORT_CONNECT_ERR          "LS_TRANS"              /** Transport connection error */
#define MSGID_LS_TRANSPORT_CLIENT_ERR           "LS_TRANS_CLIENT"       /** Failed to create transport client */
#define MSGID_LS_TRANSPORT_NETWORK_ERR          "LS_TRANS_NET"          /** Transport network error */
#define MSGID_LS_UNAME_ERR                      "LS_UNAME_ERR"          /** Can't get unique name from the message */
#define MSGID_LS_UNHANDLED_MSG                  "LS_UNHANDLD_MSG"       /** Unhandled message */
#define MSGID_LS_UNKNOWN_FAILURE                "LS_UNKNOWN_FLR"        /** Unknown failure */
#define MSGID_LS_UNKNOWN_MSG                    "LS_UNKNOWN_MSG"        /** Unknown message */
#define MSGID_LS_BAD_METHOD_FLAGS               "LS_BAD_MTHD_FLGS"      /** Invalid flags provdied in LSMethod structure */
#define MSGID_LS_BAD_VALIDATION_FLAG            "LS_BAD_VALID_FLAG"     /** Error in pre-conditions for validation flag (missing validatoin schema) */
#define MSGID_LS_PALM_SERVICE_WITH_TWO_CONTEXTS "LS_PALM_SERVICE_WITH_TWO_CONTEXTS" /** Single transport used for Palm service. Need to resolve. */
#define MSGID_LS_OLD_PALM_SERVICE_DETECTED      "LS_OLD_PALM_SERVICE_DETECTED"      /** Old Palm services are depricated. You should not LSRegister twice. */
#define MSGID_LS_REQUIRES_SECURITY              "LS_REQUIRES_SECURITY"  /** Required security groups don't match provided */
#define MSGID_LS_REQUIRES_TRUST              "LS_REQUIRES_TRUST"  /** Required trust level don't match provided */
#endif /* _LOG_IDS_H */
