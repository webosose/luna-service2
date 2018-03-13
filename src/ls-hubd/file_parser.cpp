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

#include "file_parser.hpp"

#include <functional>

#include <glib.h>
#include <pbnjson.hpp>
#include <luna-service2++/error.hpp>

#include "log.h"
#include "error.h"

#include "hub.hpp"
#include "util.hpp"
#include "service.hpp"
#include "security.hpp"
#include "manifest.hpp"
#include "file_schema.hpp"
#include "pjsax_bounce.hpp"

/** @cond INTERNAL */

using namespace std::placeholders;

#define ROLE_KEY            "role"
#define PERMISSION_KEY      "permissions"
#define EXE_NAME_KEY        "exeName"
#define TYPE_KEY            "type"
#define ALLOWED_NAMES_KEY   "allowedNames"
#define SERVICE_KEY         "service"
#define INBOUND_KEY         "inbound"
#define OUTBOUND_KEY        "outbound"
#define APP_ID_KEY          "appId"
#define VERSION_KEY         "versions"

/** Allowed service file group names */
const char* service_group_names[] = {
    "D-BUS Service",
    "DBUS Service",
    "Palm Service",
    "Luna Service",
};

#define SERVICE_NAME_KEY    "Name"          /**< key for defining service name */
#define SERVICE_EXEC_KEY    "Exec"          /**< key for executable path for
                                                 service */
#define SERVICE_TYPE_KEY    "Type"          /**< type of service (dynamic or static) */

#define SERVICE_TYPE_DYNAMIC    "dynamic"
#define SERVICE_TYPE_STATIC     "static"

FileIterator::FileIterator(const std::string& suffix)
    : _suffix(suffix)
{

}

const std::string& FileIterator::Suffix() const
{
    return _suffix;
}

FileCollector::FileCollector(const std::string& suffix)
    : FileIterator(suffix)
{

}

const std::vector<std::string>& FileCollector::Files() const
{
    return _files;
}

void FileCollector::operator()(const std::string& path)
{
    _files.push_back(path);
}

bool ProcessDirectory(const char *dirpath, void* ctx, LSError *lserror)
{
    LS_ASSERT(ctx);
    LS_ASSERT(dirpath);

    LOG_LS_DEBUG("%s: parsing directory: \"%s\"\n", __func__, dirpath);

    GErrorPtr gerror;
    auto dir = mk_ptr(g_dir_open(dirpath, 0, gerror.pptr()), g_dir_close);
    if (!dir)
    {
        if (gerror->code == G_FILE_ERROR_NOENT)
        {
            LOG_LS_DEBUG("Skipping missing directory %s", dirpath);
            return true;
        }

        _LSErrorSet(lserror, MSGID_LSHUB_DIR_OPEN_ERROR, -1, "%s: Directory open error: %s", __func__, gerror->message);
        return false;
    }

    FileIterator *iterator = static_cast<FileIterator*>(ctx);
    for (const char *fname  = g_dir_read_name(dir.get()); fname; fname = g_dir_read_name(dir.get()))
    {
        const std::string& suff = iterator->Suffix();
        if (suff.empty() || g_str_has_suffix(fname, suff.c_str()))
        {
            (*iterator)(std::string(dirpath) + "/" + fname);
        }
    }

    return true;
}

RolePtr
ParseJSONGetRole(const pbnjson::JValue &json, const std::string &path, const std::string &prefix, LSError *error)
{
    bool is_exe_role = json[EXE_NAME_KEY].isString();
    bool is_app_role = json[APP_ID_KEY].isString();

    if (!is_exe_role && !is_app_role)
    {
        _LSErrorSet(error, MSGID_LSHUB_ROLE_FILE_ERR, -1, "No application path/id present in role file (%s)",
                    path.c_str());
        return {nullptr, LSHubRoleUnref};
    }
    else if (is_exe_role && is_app_role)
    {
        _LSErrorSet(error, MSGID_LSHUB_ROLE_FILE_ERR, -1,
                    "Role file is ambiguous - both application path and id specified (%s)",  path.c_str());
        return {nullptr, LSHubRoleUnref};
    }

    std::string name = json[is_exe_role ? EXE_NAME_KEY : APP_ID_KEY].asString();
    LSHubRoleType type = _LSHubRoleTypeStringToType(json[TYPE_KEY].asString());

    std::string id = json.hasKey(EXE_NAME_KEY) ? prefix + name : name;

    auto role = mk_ptr(LSHubRoleNewRef(id, type), LSHubRoleUnref);
    for (const auto& item : json[ALLOWED_NAMES_KEY].items())
    {
        LSHubRoleAddAllowedName(role.get(), item.asString().c_str());
    }

    return std::move(role);
}

PermissionArray
ParseJSONGetPermissions(const pbnjson::JValue &json, const std::string &id)
{
    PermissionArray permissions;

    for (const auto &perm : json.items())
    {
        std::string service_name = perm[SERVICE_KEY].asString();
        auto permission = mk_ptr(LSHubPermissionNewRef(service_name, id.c_str()), LSHubPermissionUnref);
        for (const auto &item : perm[OUTBOUND_KEY].items())
        {
            std::string outname = item.asString();
            LSHubPermissionAddAllowedOutbound(permission.get(), outname.c_str());

            for (const auto &variants : GetServiceRedirectionVariants(outname.c_str()))
                LSHubPermissionAddAllowedOutbound(permission.get(), variants.c_str());
        }

        for (const auto &item : perm[INBOUND_KEY].items())
        {
            std::string inname = item.asString();
            LSHubPermissionAddAllowedInbound(permission.get(), inname.c_str());

            for (const auto &variants : GetServiceRedirectionVariants(inname.c_str()))
                LSHubPermissionAddAllowedInbound(permission.get(), variants.c_str());
        }

        permissions.push_back(std::move(permission));
    }

    return permissions;
}

bool ParseJSONGetAPIVersions(const pbnjson::JValue &json, const std::string &path, PermissionArray &perms, LSError *error)
{
    if (json.hasKey(VERSION_KEY))
    {
        for (auto &perm : perms)
        {
            pbnjson::JValue api = json[VERSION_KEY][perm->service_name];
            if (api.isValid())
            {
                if (LSHubPermissionGetAPIVersion(perm.get()).isNull())
                {
                    LSHubPermissionSetAPIVersion(perm.get(), api);
                }
                else
                {
                    _LSErrorSet(error, MSGID_LSHUB_ROLE_FILE_ERR, -1,
                                "Error reading version from the JSON file: %s. "
                                "'%s' service already has version set to '%s'.",
                                path.c_str(),
                                perm->service_name,
                                perm->version.asString().c_str());
                    return false;
                }
            }
        }
    }

    return true;
}

static inline
bool ParseRole(const pbnjson::JValue &object, const std::string &path, const std::string &prefix,
               RolePtr &role, PermissionArray &perms, LSError *lserror)
{
    role = std::move(ParseJSONGetRole(object, path, prefix, lserror));
    if (!role)
    {
        return false;
    }

    perms = std::move(ParseJSONGetPermissions(object[PERMISSION_KEY], role->id));
    ParseJSONGetAPIVersions(object, path, perms, lserror);
    return true;
}

bool ParseRoleString(const std::string &data, const std::string &prefix, RolePtr &role, PermissionArray &perms,
                     LSError *error)
{
    auto json = pbnjson::JDomParser::fromString(data, role_schema);
    if (!json)
    {
        _LSErrorSet(error, MSGID_LSHUB_ROLE_FILE_ERR, -1, "%s: failed to parse role with error: %s",
                    __func__, json.errorString().c_str());
        return false;
    }

    return ParseRole(json, std::string(), prefix, role, perms, error);
}

bool ParseRoleFile(const std::string &path, const std::string &prefix, RolePtr &role, PermissionArray &perms,
                   LSError *error)
{
    LOG_LS_DEBUG("%s: parsing JSON from file: \"%s\"", __func__, path.c_str());

    auto json = pbnjson::JDomParser::fromFile(path.c_str(), role_schema);
    if (!json)
    {
        _LSErrorSet(error, MSGID_LSHUB_ROLE_FILE_ERR, -1, "%s: failed to parse JSON file %s with error %s",
                    __func__, path.c_str(), json.errorString().c_str());
        return false;
    }

    return ParseRole(json, path, prefix, role, perms, error);
}

RolePtr
ParseJSONGetRoleOld(const pbnjson::JValue &object, const std::string &prefix, uint32_t flags)
{
    std::string exe_name = object[EXE_NAME_KEY].asString();
    // Don't add prefix for a triton service
    if (exe_name.compare(g_conf_triton_service_exe_path) != 0)
    {
        exe_name = prefix + exe_name;
    }

    LSHubRoleType rt = _LSHubRoleTypeStringToType(object[TYPE_KEY].asString(), flags);

    auto role = mk_ptr(LSHubRoleNewRef(exe_name, rt, flags), LSHubRoleUnref);
    for (const auto& allowed_name : object[ALLOWED_NAMES_KEY].items())
    {
        LSHubRoleAddAllowedName(role.get(), allowed_name.asString().c_str(), flags);
    }

    return std::move(role);
}

static inline
void ParseOldRole(const pbnjson::JValue &object, const std::string &prefix, uint32_t flags, RolePtr &role,
                  PermissionArray &perms)
{
    role = std::move(ParseJSONGetRoleOld(object[ROLE_KEY], prefix, flags));
    perms = std::move(ParseJSONGetPermissions(object[PERMISSION_KEY], role->id));
    for (auto& perm : perms) perm->perm_flags = flags;
}

bool ParseOldRoleString(const std::string &data, const std::string &prefix, uint32_t flags, RolePtr &role,
                      PermissionArray &perms, LSError *error)
{
    auto json = pbnjson::JDomParser::fromString(data, old_role_schema);
    if (!json)
    {
        _LSErrorSet(error, MSGID_LSHUB_ROLE_FILE_ERR, -1, "%s: failed to parse role with error: %s",
                    __func__, json.errorString().c_str());
        return false;
    }

    ParseOldRole(json, prefix, flags, role, perms);
    return true;
}

bool ParseOldRoleFile(const std::string &path, const std::string &prefix, uint32_t flags, RolePtr &role,
                      PermissionArray &perms, LSError *error)
{
    LOG_LS_DEBUG("%s: parsing JSON from file: \"%s\"", __func__, path.c_str());
    LOG_LS_WARNING(MSGID_LSHUB_ROLE_DEPRECATED, 2
                   , PMLOGKS("FILE", LS__FILE__BASENAME)
                   , PMLOGKFV("LINE", "%d", __LINE__)
                   , "Deprecated ls2 permissions model is used (separated role files for public/private bus). Role file:\"%s\""
                   , path.c_str());

    auto json = pbnjson::JDomParser::fromFile(path.c_str(), old_role_schema);
    if (!json)
    {
        _LSErrorSet(error, MSGID_LSHUB_ROLE_FILE_ERR, -1, "%s: failed to parse JSON file %s with error: %s",
                    __func__, path.c_str(), json.errorString().c_str());
        return false;
    }

    ParseOldRole(json, prefix, flags, role, perms);
    return true;
}

/**
 ********************************************************************************
 * @brief Parse (and validate) a service file.
 *
 * @verbatim
 * Example:
 *
 * [Luna Service]
 * Name=com.palm.foo
 * Exec=/path/to/executable
 * @endverbatim
 *
 * @param service_file_dir   IN  path to service file
 * @param service_file_name  IN  service file name
 * @param prefix             IN  prefix for the removable media
 * @param lserror            OUT set on error
 *
 * @retval  service with ref count of 1 on success
 * @retval  NULL on failure
 ********************************************************************************
*/

typedef std::unique_ptr<GKeyFile, void(*)(GKeyFile*)> KeyFile;

static inline
_Service* ParseService(const KeyFile &key_file, const std::string &path, const std::string &prefix, LSError *error)
{
    GErrorPtr gerror;

    gsize group_len = 0;
    auto groups = mk_ptr(g_key_file_get_groups(key_file.get(), &group_len), g_strfreev);

    if (!groups)
    {
        _LSErrorSet(error, MSGID_LSHUB_SERVICE_FILE_ERR, -1, "No service group in key file: \"%s\"\n", path.c_str());
        return nullptr;
    }

    const char *service_group = nullptr;
    for (size_t i = 0; i < group_len && !service_group; i++)
    {
        size_t j = 0;
        for (; j < sizeof(service_group_names)/sizeof(*service_group_names); j++)
        {
            if (strcmp(groups.get()[i], service_group_names[j]) == 0)
            {
                service_group = service_group_names[j];
                break;
            }
        }

        if (j == sizeof(service_group_names)/sizeof(*service_group_names))
        {
            LOG_LS_WARNING(MSGID_LSHUB_UNKNOWN_GROUP, 2,
                           PMLOGKS("GROUP", groups.get()[i]),
                           PMLOGKS("PATH", path.c_str()),
                           "Found unknown group in key file");
        }
    }

    if (!service_group)
    {
        _LSErrorSet(error, MSGID_LSHUB_SERVICE_FILE_ERR, -1,
                    "Could not find valid service group in key file: \"%s\"\n", path.c_str());
        return nullptr;
    }

    /* check for the keys */

    if (!g_key_file_has_key(key_file.get(), service_group, SERVICE_NAME_KEY, gerror.pptr()) ||
        !g_key_file_has_key(key_file.get(), service_group, SERVICE_EXEC_KEY, gerror.pptr()))
    {
        _LSErrorSet(error, MSGID_LSHUB_SERVICE_FILE_ERR, -1,
                    "Error finding key: \"%s\" in key file: \"%s\"\n", SERVICE_NAME_KEY, path.c_str());
        return nullptr;
    }

    /* provided services -- can be more than one */
    gsize provided_services_len = 0;
    auto provided_services = mk_ptr(g_key_file_get_string_list(key_file.get(), service_group, SERVICE_NAME_KEY,
                                                               &provided_services_len, gerror.pptr()), g_strfreev);

    if (!provided_services)
    {
        _LSErrorSet(error, MSGID_LSHUB_SERVICE_FILE_ERR, -1,
                    "No services found in key file: \"%s\", message: \"%s\"\n", path.c_str(), gerror->message);
        return nullptr;
    }

    /* exec string */
    auto exec_str = mk_ptr(g_key_file_get_value(key_file.get(), service_group, SERVICE_EXEC_KEY, gerror.pptr()), g_free);
    if (!exec_str)
    {
        _LSErrorSet(error, MSGID_LSHUB_SERVICE_FILE_ERR, -1,
                    "No \"%s\" key found in key file: \"%s\", message: \"%s\"\n",
                    SERVICE_EXEC_KEY, path.c_str(), gerror->message);
        return nullptr;
    }

    if (!prefix.empty())
    {
        exec_str.reset(g_build_filename(prefix.c_str(), exec_str.get(), nullptr));
    }

    /* check for static string -- default to dynamic if we don't find one */
    bool is_dynamic = true;
    auto type_str = mk_ptr(g_key_file_get_value(key_file.get(), service_group, SERVICE_TYPE_KEY, gerror.pptr()), g_free);
    if (type_str)
    {
        if (strcmp(type_str.get(), SERVICE_TYPE_DYNAMIC) == 0)
        {
            is_dynamic = true;
        }
        else if (strcmp(type_str.get(), SERVICE_TYPE_STATIC) == 0)
        {
            is_dynamic = false;
        }
        else
        {
            _LSErrorSet(error, MSGID_LSHUB_SERVICE_FILE_ERR, -1, "Unrecognized service type: \"%s\"", type_str.get());
            return nullptr;
        }
    }

    /* we've got everything we need */
    for (unsigned int i = 0; i < provided_services_len; i++)
    {
        LOG_LS_DEBUG("%s: service file: \"%s\", provided service: \"%s\"\n",
                     __func__,  path.c_str(), provided_services.get()[i]);
    }

    std::string exec_str_with_prefix;
    if (g_conf_dynamic_service_exec_prefix)
    {
        exec_str_with_prefix = g_conf_dynamic_service_exec_prefix + std::string{" "} + exec_str.get();
    }
    else
    {
        exec_str_with_prefix = std::string{exec_str.get()};
    }

    LOG_LS_DEBUG("%s: service file: \"%s\", exec string: \"%s\"\n",
                 __func__,  path.c_str(), exec_str_with_prefix.c_str());

    return _ServiceNewRef((const char**)provided_services.get(), provided_services_len,
                          exec_str_with_prefix.c_str(), is_dynamic, path.c_str());
}

_Service* ParseServiceString(const std::string &data, const std::string &prefix, LSError *error)
{
    GErrorPtr gerror;
    KeyFile key_file(g_key_file_new(), g_key_file_free);
    if (!g_key_file_load_from_data(key_file.get(), data.c_str(), data.size(), G_KEY_FILE_NONE, gerror.pptr()))
    {
        _LSErrorSet(error, MSGID_LSHUB_SERVICE_FILE_ERR, -1, "Error loading key file: \"%s\"\n", gerror->message);
        return nullptr;
    }

    return ParseService(key_file, std::string(), prefix, error);
}

_Service* ParseServiceFile(const std::string &path, const std::string &prefix, LSError *error)
{
    LOG_LS_DEBUG("%s: parsing file: \"%s\"\n", __func__, path.c_str());

    GErrorPtr gerror;
    KeyFile key_file(g_key_file_new(), g_key_file_free);
    if (!g_key_file_load_from_file(key_file.get(), path.c_str(), G_KEY_FILE_NONE, gerror.pptr()))
    {
        _LSErrorSet(error, MSGID_LSHUB_SERVICE_FILE_ERR, -1, "Error loading key file: \"%s\"\n", gerror->message);
        return nullptr;
    }

    return ParseService(key_file, path, prefix, error);
}

namespace {
    /// General purpose parser for jsons that look like {"a": ["x","y","z"]}
    ///
    /// JSON expected to match that schema. Otherwise behavior is undefined.
    class JParseKeyedStrArrays
    {
        typedef std::function<void(const std::string &, pbnjson::JInput) noexcept> handler_type;

        bool have_key = false;
        handler_type handler;
        LSError *lserror;
        std::string active_key;

    public:
        using JInput = pbnjson::JInput;

        JParseKeyedStrArrays(handler_type handler, LSError *lserror = nullptr) :
            handler{std::move(handler)},
            lserror{lserror}
        {}

        bool parseFile(const char *filename, const pbnjson::JSchema &schema)
        {
            gchar *buf;
            gsize len;
            GErrorPtr err;
            if (!g_file_get_contents(filename, &buf, &len, lserror ? err.pptr() : nullptr))
            {
                if (lserror)
                {
                    g_prefix_error(err.pptr(),
                                   "Failed to get contents of json file %s: ", filename);
                    _LSErrorSetFromGError(lserror, MSGID_LSHUB_JSON_READ_ERR, err.release());
                }
                return false;
            }
            bool result = parse(pbnjson::JInput{buf, len}, schema);
            g_free(buf);
            return result;
        }

        bool parse(pbnjson::JInput input, const pbnjson::JSchema &schema)
        {
            static auto *callbacks = PJSAXBounce<JParseKeyedStrArrays>::callbacks();
            if (lserror)
            {
                jerror *err = nullptr;
                bool status = jsax_parse_with_callbacks(input, schema.peek(), callbacks, this, &err);

                if (!status)
                {
                    int err_msg_len = jerror_to_string(err, nullptr, 0); // calc size
                    char err_msg[err_msg_len+1];
                    (void) jerror_to_string(err, err_msg, sizeof(err_msg)); // render error
                    jerror_free(err); // no more need in jerror

                    _LSErrorSet(lserror, MSGID_LSHUB_JSON_ERR, -1, "Failed to parse json: %s", err_msg);
                }

                return status;
            }
            else
            {
                return jsax_parse_with_callbacks(input, schema.peek(), callbacks, this, nullptr);
            }
        }

        // actual work
        bool jsonObjectKey(JInput key)
        {
            have_key = true;
            active_key.assign(key.m_str, key.m_len);
            return true;
        }

        bool jsonString(JInput value)
        {
            assert(have_key);
            handler(active_key, value);
            return true;
        }

        // boilerplate overrides to get objects and array accepted
        bool jsonObjectOpen() { return true; }
        bool jsonObjectClose() { return true; }
        bool jsonArrayOpen() { assert(have_key); return true; }
        bool jsonArrayClose() { return true; }

        // unused
        bool jsonNumber(JInput) { return false; }
        bool jsonBoolean(bool) { return false; }
        bool jsonNull() { return false; }
    };

} // anonymous namespace

static void ParseHandler(CategoryMap &map, const std::string &key, pbnjson::JInput value)
{
    const char *fixed = g_intern_string(std::string(value.m_str, value.m_len).c_str());
    map[key].push_back(fixed);
}

bool ParseRequiresString(const std::string &data, CategoryMap &requires, LSError *error)
{
    JParseKeyedStrArrays parser(std::bind(&ParseHandler, std::ref(requires), _1, _2), error);
    return parser.parse(data, client_permissions_schema);
}

bool ParseRequiresFile(const std::string &path, CategoryMap &requires, LSError *error)
{
    LOG_LS_DEBUG("%s: parsing JSON from file: \"%s\"", __func__, path.c_str());

    JParseKeyedStrArrays parser(std::bind(&ParseHandler, std::ref(requires), _1, _2), error);
    return parser.parseFile(path.c_str(), client_permissions_schema);
}

bool ParseProvidesString(const std::string &data, CategoryMap &provides, LSError *error)
{
    JParseKeyedStrArrays parser(std::bind(&ParseHandler, std::ref(provides), _1, _2), error);
    return parser.parse(data, api_permissions_schema);
}

bool ParseProvidesFile(const std::string &path, CategoryMap &provides, LSError *error)
{
    LOG_LS_DEBUG("%s: parsing JSON from file: \"%s\"", __func__, path.c_str());

    JParseKeyedStrArrays parser(std::bind(&ParseHandler, std::ref(provides), _1, _2), error);
    return parser.parseFile(path.c_str(), api_permissions_schema);
}

/** @endcond INTERNAL */
