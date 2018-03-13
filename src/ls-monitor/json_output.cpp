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

#include <string.h>
#include <sstream>
#include <pbnjson.hpp>

#include "json_output.hpp"

using namespace pbnjson;

/**
 * Print monitor message type
 */
const char *
JsonOutputFormatter::FormatType(const _LSMonitorMessageType message_type)
{
    switch (message_type)
    {
    case _LSMonitorMessageTypeTx:
        return "TX";
    case _LSMonitorMessageTypeRx:
        return "RX";
    default:
        LOG_LS_ERROR(MSGID_LS_UNKNOWN_MSG, 1, PMLOGKFV("TYPE", "%d", message_type), "Unknown monitor message type");
        return "UN";
    }
}

/**
 * Prepares time for print
 */
double
JsonOutputFormatter::ComputeTime(const struct timespec *time)
{
    return ((double)(time->tv_sec)) + (((double)time->tv_nsec) / (double)1000000000.0);
}

JsonOutputFormatter::JsonOutputFormatter(FILE *_file):
    file(_file)
{
}

void
JsonOutputFormatter::PrintMessage(_LSTransportMessage *message)
{
    const _LSMonitorMessageData *message_data = _LSTransportMessageGetMonitorMessageData(message);
    _LSTransportMessageType type = _LSTransportMessageGetType(message);
    const char *app_id = _LSTransportMessageGetAppId(message);
    const char *payload = _LSTransportMessageGetPayload(message);
    const char* service_name = _LSTransportMessageGetSenderServiceName(message);
    const char* sender_unique_name = _LSTransportMessageGetSenderUniqueName(message);
    const char* destination = _LSTransportMessageGetDestServiceName(message);
    const char* destination_unique_name = _LSTransportMessageGetDestUniqueName(message);
    const char *type_name;
    gboolean hasMethod;

    // Add mandatory fields
    JValue output = JObject({{"time",ComputeTime(&message_data->timestamp)},
                             {"transport",FormatType(message_data->type)},
                             {"serial",(int64_t)message_data->serial},
                             {"token", (int64_t)_LSTransportMessageGetToken(message)},
                             {"sender", service_name ? JValue(service_name) : JValue()},
                             {"senderUniqueName", sender_unique_name ? JValue(sender_unique_name): JValue()},
                             {"destination", destination ? JValue(destination): JValue()},
                             {"destinationUniqueName", destination_unique_name ? JValue(destination_unique_name): JValue()}});

    //sort through message types and add message specific stuff
    switch (type)
    {
    case _LSTransportMessageTypeSignal:
        hasMethod = true;
        type_name = "signal";
        break;

    case _LSTransportMessageTypeCancelMethodCall:
        hasMethod = true;
        type_name = "callCancel";
        break;

    case _LSTransportMessageTypeMethodCall:
        hasMethod = true;
        type_name = "call";
        break;

    case _LSTransportMessageTypeReply:
        hasMethod = false;
        type_name = "return";
        output.put("replyToken", (int64_t)_LSTransportMessageGetReplyToken(message));
        break;

    case _LSTransportMessageTypeError:
        type_name = "error";
        hasMethod = false;
        break;

    default:
        type_name = NULL;
        hasMethod = false;
        break;
    }

    //print type name
    if (type_name != NULL)
    {
        output.put("type", type_name);
    }
    else
    {
        std::ostringstream stringStream;
        stringStream << "unknown " << type;
        output.put("type", stringStream.str());
    }

    //print method
    if (hasMethod)
    {
        output.put("methodCategory", _LSTransportMessageGetCategory(message));
        output.put("method", _LSTransportMessageGetMethod(message));
    }

    if (app_id != NULL)
    {
        output.put("appId", app_id);
    }

    //Check if payload is valid JSON
    if (payload != NULL)
    {
        JValue value = JDomParser::fromString(payload, JSchema::AllSchema());

        if (value.isValid()) {
            output.put("payload", value);
        }
        else
        {
            // Payload not valid JSON, add it to raw tag
            output.put("rawPayload", payload);
        }
    }

	// Print the JSON message as single line.
    fprintf(file, "%s\n", output.stringify().c_str());
}
