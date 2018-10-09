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

#include "hub_service.hpp"

#include <pbnjson.hpp>
#include <luna-service2++/error.hpp>
#include <luna-service2++/payload.hpp>

extern "C" {
#include "uri.h"
#include "transport.h"
}
#include "hub.hpp"
#include "security.hpp"
#include "file_parser.hpp"
#include "active_permission_map.hpp"
#include "permission.hpp"

static const pbnjson::JValue DEFAULT_API_VERSION("1.0");

static auto is_call_allowed_schema = pbnjson::JSchema::fromString(R"(
{
    "type": "object",
    "properties":
    {
        "uri": { "type": "string" },
        "requester": { "type": "string" }
    },
    "required": ["uri", "requester"]
}
)");

static auto manifests_dir_schema = pbnjson::JSchema::fromString(R"(
{
    "type": "object",
    "properties":
    {
        "prefix": { "type": "string" },
        "dirpath": { "type": "string" }
    },
    "required": ["prefix", "dirpath"]
})");

static auto one_manifest_schema = pbnjson::JSchema::fromString(R"(
{
    "type": "object",
    "properties":
    {
        "prefix": { "type": "string" },
        "path": { "type": "string" }
    },
    "required": ["prefix", "path"]
})");

static auto get_service_api_versions_schema = pbnjson::JSchema::fromString(R"(
{
    "type": "object",
    "properties":
    {
        "services": { "type": "array", "items": { "type": "string"} }
    },
    "required": ["services"]
})");

static auto query_service_permissions_schema = pbnjson::JSchema::fromString(R"(
{
    "type": "object",
    "properties": {
        "service": {"type": "string"}
    },
    "required": ["service"]
}
)");

static inline
std::string make_error(int error_code, const std::string &error_text)
{
    std::string error;
    error = "{";
    error += "\"returnValue\": false, ";
    error += "\"errorCode\": " + std::to_string(error_code) + ",";
    error += "\"errorText\": \"" + error_text + "\"";
    error += "}";
    return error;
}

HubService& HubService::instance()
{
    static HubService object;
    return object;
}

HubService::HubService()
    : _methods_map {
        {"isCallAllowed", &HubService::IsCallAllowed},
        {"addOneManifest", &HubService::AddOneManifest},
        {"removeOneManifest", &HubService::RemoveOneManifest},
        {"addManifestsDir", &HubService::AddManifestsDir},
        {"removeManifestsDir", &HubService::RemoveManifestsDir},
        {"getServiceAPIVersions", &HubService::GetServiceApiVersions},
        {"queryServicePermissions", &HubService::QueryServicePermissions},
    }
{
}

std::string HubService::IsCallAllowed(_LSTransportMessage *message, const char *payload)
{
	LOG_LS_DEBUG("Hub_Service: %s\n", __func__);
    (void)message;

    auto object = pbnjson::JDomParser::fromString(payload, is_call_allowed_schema);
    if (!object)
    {
        return make_error(-1, object.errorString());
    }

    LS::Error error;
    auto lsuri = mk_ptr(LSUriParse(object["uri"].asString().c_str(), error.get()), LSUriFree);
    if (error.isSet())
    {
        return make_error(error->error_code, error->message);
    }

    bool allowed = LSHubIsCallAllowed(object["requester"].asString().c_str(),
                                      lsuri->serviceName, lsuri->objectPath, lsuri->methodName);

    std::string reply;
    reply += R"({"returnValue": true, "allowed": )";
    reply += allowed ? "true" : "false";
    reply += "}";
    return reply;
}

std::string HubService::AddOneManifest(_LSTransportMessage *message, const char *payload)
{
	LOG_LS_DEBUG("Hub_Service: %s\n", __func__);
    (void)message;

    auto object = pbnjson::JDomParser::fromString(payload, one_manifest_schema);
    if (!object)
    {
        return make_error(-1, object.errorString());
    }

    const char *service = message->client->service_name;
    if (!service || !LSHubIsCallAllowed(service, "com.webos.service.bus", "/", "addOneManifest"))
    {
        std::string safe_string = service ? service : "(null)";
        safe_string += " is not allowed to call addOneManifest";
        return make_error(-1, safe_string);
    }

    std::string prefix = object["prefix"].asString();
    if (prefix == "/")
        prefix = "";
    std::string path = BuildFilename(prefix, object["path"].asString());

    LS::Error error;
    auto &security_data = SecurityData::CurrentSecurityData();
    bool result = prefix == "" && security_data.IsManifestNonVolatile(path)
                  // Don't cache preinstalled manifests from RO partition into RAM
                ? security_data.AddManifest(path, prefix, error)
                : security_data.AddExternalManifest(path, prefix, false, error);
    if (!result)
    {
        if (error.isSet())
            return make_error(error->error_code, error->message);
        return make_error(-1, "Cannot add manifest: reason unknown");
    }

    return R"({"returnValue":true})";
}

std::string HubService::RemoveOneManifest(_LSTransportMessage *message, const char *payload)
{
	LOG_LS_DEBUG("Hub_Service: %s\n", __func__);
    (void)message;

    auto object = pbnjson::JDomParser::fromString(payload, one_manifest_schema);
    if (!object)
    {
        return make_error(-1, object.errorString());
    }

    const char *service = message->client->service_name;
    if (!service || !LSHubIsCallAllowed(service, "com.webos.service.bus", "/", "removeOneManifest"))
    {
        std::string safe_string = service ? service : "(null)";
        safe_string += " is not allowed to call removeOneManifest";
        return make_error(-1, safe_string);
    }

    std::string prefix = object["prefix"].asString();
    if (prefix == "/")
        prefix = "";
    std::string path = BuildFilename(prefix, object["path"].asString());

    auto &security_data = SecurityData::CurrentSecurityData();
    if (prefix == "" && security_data.IsManifestNonVolatile(path))
        security_data.RemoveManifest(path);
    else
        security_data.RemoveExternalManifest(path, prefix);

    return R"({"returnValue":true})";
}

std::string HubService::AddManifestsDir(_LSTransportMessage *message, const char *payload)
{
	LOG_LS_DEBUG("Hub_Service: %s\n", __func__);
    auto object = pbnjson::JDomParser::fromString(payload, manifests_dir_schema);
    if (!object)
    {
        return make_error(-1, object.errorString());
    }

    const char *service = message->client->service_name;
    if (!service || !LSHubIsCallAllowed(service, "com.webos.service.bus", "/", "addManifestsDir"))
    {
        std::string safe_string = service ? service : "(null)";
        safe_string += " is not allowed to call addManifestsDir";
        return make_error(-1, safe_string);
    }

    std::string prefix = object["prefix"].asString();
    std::string dir = BuildFilename(prefix, object["dirpath"].asString());

    LS::Error lserror;
    FileCollector collector;
    if (!ProcessDirectory(dir.c_str(), &collector, lserror))
    {
        return make_error(-1, lserror.what());
    }

    pbnjson::JArray not_loaded;
    SecurityData &sd = SecurityData::CurrentSecurityData();
    for (const auto &f : collector.Files())
    {
        LSErrorInit(lserror);
        if (!sd.AddExternalManifest(f, prefix, false, lserror))
        {
            not_loaded.append(pbnjson::JObject{{ "file:", f }, { "error", lserror.what() }});
        }
    }

    pbnjson::JObject reply;
    if (not_loaded.arraySize() == 0)
    {
        reply.put("returnValue", true);
    }
    else
    {
        reply.put("returnValue", false);
        reply.put("errorCode", -1);
        reply.put("errorText", std::string("Not all manifests were loaded"));
        reply.put("manifests", not_loaded);
    }

    return reply.stringify();
}

std::string HubService::RemoveManifestsDir(_LSTransportMessage *message, const char *payload)
{
	LOG_LS_DEBUG("Hub_Service: %s\n", __func__);
    auto object = pbnjson::JDomParser::fromString(payload, manifests_dir_schema);
    if (!object)
    {
        return make_error(-1, object.errorString());
    }

    const char *service = message->client->service_name;
    if (!service || !LSHubIsCallAllowed(service, "com.webos.service.bus", "/", "removeManifestsDir"))
    {
        std::string safe_string = service ? service : "(null)";
        safe_string += " is not allowed to call removeManifestsDir";
        return make_error(-1, safe_string);
    }

    std::string prefix = object["prefix"].asString();
    std::string dir = BuildFilename(prefix, object["dirpath"].asString());

    LS::Error lserror;
    FileCollector collector;
    if (!ProcessDirectory(dir.c_str(), &collector, lserror))
    {
        return make_error(-1, lserror.what());
    }

    SecurityData &sd = SecurityData::CurrentSecurityData();

    if (collector.Files().empty())
        sd.FetchManifestFiles(dir, &collector);

    for (const auto &f : collector.Files())
    {
        sd.RemoveExternalManifest(f, prefix);
    }

    return R"({"returnValue":true})";
}

std::string HubService::GetServiceApiVersions(_LSTransportMessage *message, const char *payload)
{
	LOG_LS_DEBUG("Hub_Service: %s\n", __func__);
    (void)message;

    auto object = pbnjson::JDomParser::fromString(payload, get_service_api_versions_schema);
    if (!object)
    {
        return make_error(-1, object.errorString());
    }

    bool retVal = true;
    pbnjson::JValue valid_versions = pbnjson::Object();
    pbnjson::JValue invalid_versions = pbnjson::Array();
    for (const auto& name : object["services"].items())
    {
        auto permission = SecurityData::CurrentSecurityData().permissions.LookupServicePermissions(name.asString().c_str());

        std::string destination_service_name;

        if (permission)
        {
              LSHubPermission *p = static_cast<LSHubPermission *>(permission->permissions->data);
              destination_service_name = std::string(name.asString().c_str());

              if ((nullptr == p->service_name) || strcmp(p->service_name ,name.asString().c_str()))
              {
                 for (const auto& servicename : GetServiceRedirectionVariants(name.asString().c_str()))
                 {
                     permission = SecurityData::CurrentSecurityData().permissions.LookupServicePermissions(servicename.c_str());
                     if (permission)
                     {
                         LSHubPermission *p = static_cast<LSHubPermission *>(permission->permissions->data);
                         if (p->service_name && !strcmp(p->service_name ,servicename.c_str()))
                         {
                             destination_service_name = std::string(servicename);
                             break;
                         }
                     }
                 }
             }
        }

        if (permission)
        {
            // Now, when we found a list of permissions for given service name
            // coming from different role files, we'll have to choose one of
            // them. Ideally, there should be only one entry in the list; and
            // that's true for real services. Multiple entries should contain
            // the same version for all executables/applications.

          LSHubPermission *p = static_cast<LSHubPermission *>(permission->permissions->data);
          if (p->service_name && !strcmp(p->service_name ,destination_service_name.c_str()))
          {
             const auto &version = LSHubPermissionGetAPIVersion(p);
             valid_versions.put(name, version.isNull() ? DEFAULT_API_VERSION : version);
          }
          else
          {
             retVal = false;
             invalid_versions.append(name);
          }
        }
        else
        {
            retVal = false;
            invalid_versions.append(name);
        }
    }

    auto reply = pbnjson::JObject {{"versions", valid_versions}, {"returnValue", retVal}};
    if (!retVal) reply.put("unknown", invalid_versions);

    return reply.stringify();
}

void HubService::HandleMethodCall(_LSTransportMessage *message)
{
	LOG_LS_DEBUG("Hub_Service: %s\n", __func__);
    _LSTransportMessageIter iter;
    _LSTransportMessageIterInit(message, &iter);

    const char *method = nullptr;
    const char *payload = nullptr;

    _LSTransportMessageGetString(&iter, &method);

    _LSTransportMessageIterNext(&iter);
    _LSTransportMessageGetString(&iter, &payload);

    assert(method && payload);

    std::string reply;

    auto found = _methods_map.find(method);
    if (found != _methods_map.end())
    {
        reply =  (this->*found->second)(message, payload);
        if (reply.empty()) return; // delayed
    }
    else
    {
        reply = make_error(-1, "Invalid parameters to LSCall.");
    }

    LS::Error error;
    if (!_LSTransportSendReply(message, LS::Payload(reply.c_str()), error.get()))
    {
        LOG_LSERROR(MSGID_LSHUB_SENDMSG_ERROR, error.get());
    }
}

namespace {

std::string RespondServicePermissions(const CategoryMap &provided, const Groups &required)
{
	LOG_LS_DEBUG("Hub_Service: %s\n", __func__);
    static_assert(std::is_scalar<Groups::value_type>::value,
                  "We'll iterate scalar Groups items by value in this function");

    // Prepare response data
    auto response = pbnjson::JObject{{"returnValue", true}};

    // Add api permissions to the response
    auto api_permissions = pbnjson::JObject{};
    for (const auto &category : provided)
    {
        auto value = pbnjson::JArray{};
        for (auto group : category.second)
            value.append(group);
        api_permissions.put(category.first, value);
    }
    response.put("api", api_permissions);

    // Add client permissions to the response
    auto client_permissions = pbnjson::JArray{};
    for (auto group : required)
    {
        client_permissions.append(group);
    }
    response.put("client", client_permissions);

    return response.stringify();
}

} //namespace

std::string HubService::QueryServicePermissions(_LSTransportMessage *message, const char *payload)
{
	LOG_LS_DEBUG("Hub_Service: %s\n", __func__);
    (void)message;

    // Parse message payload
    auto object = pbnjson::JDomParser::fromString(payload, query_service_permissions_schema);
    if (!object)
    {
        return make_error(-1, object.errorString());
    }

    auto service_name = object["service"].asString();

    // First look up into active service permissions. These may contain more
    // accurate data, because for instance compatibility groups `private' and
    // `public' are added upon service registration.

    LSHubPermission *active_perm =
        LSHubActivePermissionMapLookup(service_name.c_str());
    if (active_perm)
    {
        return RespondServicePermissions(active_perm->provides, active_perm->requires);
    }

    // Query permissions from the security data
    const auto &groups = SecurityData::CurrentSecurityData().groups;
    const auto &provided = groups.GetProvided(service_name.c_str());
    const auto &required = groups.GetRequired(service_name.c_str());

    return RespondServicePermissions(provided, required);
}
