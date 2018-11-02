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

#include "manifest.hpp"

#include <fstream>
#include <algorithm>

#include <pbnjson.hpp>
#include <luna-service2++/error.hpp>

#include "util.hpp"
#include "file_parser.hpp"
#include "file_schema.hpp"
#include "security.hpp"
#include "conf.hpp"

std::unordered_map<std::string, std::string> external_manifests;
std::unordered_map<std::string, std::string> external_manifests_data;

/*void DumpTrustMap(const TrustMap &trust_level, std::string &dump)
{
    LOG_LS_DEBUG("NILESH >>>>>>>>>>>> %s : DUMPING COMPLETE TRUST MAP", __func__);
    for(const auto& e : trust_level)
    {
        dump += "Group: " + e.first + " ";
        for(auto &str : e.second)
        {    dump += str; dump += " "; }
    }
    LOG_LS_DEBUG("NILESH >>>>>>>>>> %s : DUMPING COMPLETE TRUST MAP - END", __func__);
}

void DumpTrustMapToFile(std::string filename, ServiceToTrustMap &trust_level, std::string title)
{
    if (filename.empty()) return;
    if (trust_level.size() == 0) return;

    std::ofstream file;
    std::string name = "/tmp/" + std::string(filename);
    file.open(name);
    if(file.is_open())
    {
        file << "TrustMap for => " << title << std::endl;
        std::string trustmap;
        for(const auto& e : trust_level)
        {
            file << "Service Name: " << e.first << std::endl;
            std::string dump;
            DumpTrustMap(e.second, dump);
            file << dump << std::endl;
        }
        file.close();
    }
}*/

Manifest::Manifest(const std::string &path, const std::string &prefix)
    : path(path)
    , prefix(prefix)
{

}

Manifest::Manifest(const std::string &id, SemanticVersion &&version)
    : id(id)
    , version(std::move(version))
{

}

bool Manifest::parse(LSError *error)
{
    auto json = pbnjson::JDomParser::fromFile(path.c_str(), manifest_schema);
    if (!json)
    {
        _LSErrorSet(error, MSGID_LSHUB_MANIFEST_FILE_ERROR, -1, "Manifest \"%s\" parse error: \"%s\"",
                    path.c_str(), json.errorString().c_str());
        return false;
    }

    SemanticVersion v(json["version"].asString());
    if (!v.isValid())
    {
        _LSErrorSet(error, MSGID_LSHUB_MANIFEST_FILE_ERROR, -1, "Manifest \"%s\" has invalid version: \"%s\"",
                    path.c_str(), json["version"].asString().c_str());
        return false;
    }

    id = json["id"].asString();
    version = std::move(v);

    return true;
}

bool ManifestData::ProcessManifest(const std::string &path, const std::string &prefix, ManifestData &data, LSError *error)
{
    auto manifest = pbnjson::JDomParser::fromFile(path.c_str(), manifest_schema);
    LS_ASSERT(manifest);

    return ProcessManifest(manifest, prefix, data, error);
}

bool ManifestData::ProcessManifest(const pbnjson::JValue &manifest, const std::string &prefix, ManifestData &data,LSError *error)
{
    LOG_LS_DEBUG("NILESH>>>>: %s\n", __func__);
    for (const auto &f : manifest["roleFiles"].items())
    {
        Permissions perms;
        RolePtr role(nullptr, LSHubRoleUnref);
        ServiceToTrustMap trust_level_required;
		std::string trustLevel;
        if (!ParseRoleFile(BuildFilename(prefix, f.asString()), prefix, role, perms, trust_level_required, trustLevel,error))
        {
            return false;
        }
        std::string file_name(BuildFilename(prefix, f.asString()));
        //DumpTrustMapToFile("ManifestData_ProcessManifest_trust_level_required_" + extract_filename(file_name), trust_level_required, extract_filename(file_name));
        data.roles.push_back(std::move(role));
		data.trustLevel = trustLevel;
        std::move(perms.begin(), perms.end(), std::back_inserter(data.perms));

        //TBD: Fill trust map for required trust
        // Make sure that require map is filled properly while parsing role file
         for (const auto &e : trust_level_required)
        {
            LOG_LS_DEBUG("NILESH >>>> %s : for service [%s]", __func__, e.first);
                data.trust_level_required[e.first] = (e.second);
        }
        //DumpTrustMapToFile("ManifestData_ProcessManifest_data.trust_level_required_" + extract_filename(file_name), data.trust_level_required, extract_filename(file_name));
    }

    for (const auto &f : manifest["roleFilesPub"].items())
    {
        Permissions perms;
        RolePtr role(nullptr, LSHubRoleUnref);
        if (!ParseOldRoleFile(BuildFilename(prefix, f.asString()), prefix, PUBLIC_BUS_ROLE, role, perms, error))
        {
            return false;
        }

        // Don't add the role  for a triton  service, since triton will push
        // the role file when it wants to use it
        if (role->id.compare(g_conf_triton_service_exe_path) != 0)
        {
            data.roles.push_back(std::move(role));
        }
        std::move(perms.begin(), perms.end(), std::back_inserter(data.perms));
    }

    for (const auto &f : manifest["roleFilesPrv"].items())
    {
        Permissions perms;
        RolePtr role(nullptr, LSHubRoleUnref);
        if (!ParseOldRoleFile(BuildFilename(prefix, f.asString()), prefix, PRIVATE_BUS_ROLE, role, perms, error))
        {
            return false;
        }

        // Don't add the role  for a triton  service, since triton will push
        // the role file when it wants to use it
        if (role->id.compare(g_conf_triton_service_exe_path) != 0)
        {
            data.roles.push_back(std::move(role));
        }
        std::move(perms.begin(), perms.end(), std::back_inserter(data.perms));
    }

    for (const auto &f : manifest["serviceFiles"].items())
    {
        ServicePtr service(ParseServiceFile(BuildFilename(prefix, f.asString()), prefix, error), _ServiceUnref);
        if (!service)
        {
            return false;
        }

        data.services.push_back(std::move(service));
    }

    for (const auto &f : manifest["clientPermissionFiles"].items())
    {
        CategoryMap reqs;
        if (!ParseRequiresFile(BuildFilename(prefix, f.asString()), reqs, error))
        {
            return false;
        }

        for (const auto &child : reqs)
        {
            data.requires[child.first].insert(child.second);
        }
    }

    for (const auto &f : manifest["apiPermissionFiles"].items())
    {
        CategoryMap provs;
        if (!ParseProvidesFile(BuildFilename(prefix, f.asString()), provs, error))
        {
            return false;
        }

        for (const auto &child : provs)
        {
            data.provides[child.first].insert(child.second);
        }
    }

    // Parse groups provided by services
    for (const auto &f : manifest["groupsFiles"].items())
    {
        LOG_LS_DEBUG("NILESH>>>> Parsing %s \n", f.asString().c_str());
        ServiceToTrustMap trust_level_provided;
        if (!ParseGroupsFile(BuildFilename(prefix, f.asString()), trust_level_provided, error))
        {
            return false;
        }
        std::string file_name(BuildFilename(prefix, f.asString()));
        //DumpTrustMapToFile( "ManifestData_ProcessManifest_trust_level_provided_" + extract_filename(file_name), trust_level_provided, extract_filename(file_name));
        for (const auto &e : trust_level_provided)
        {
            LOG_LS_DEBUG("NILESH >>>> %s : for service [%s]", __func__, e.first);
            data.trust_level_provided[e.first] = (e.second);
        }
        //DumpTrustMapToFile( "ManifestData_ProcessManifest_data.trust_level_provided_" + extract_filename(file_name), data.trust_level_provided, extract_filename(file_name));
        LOG_LS_DEBUG("NILESH>>>> Completed Parsing %s \n", f.asString().c_str());
    }
    return true;
}

ExternalManifestData::ExternalManifestData(const std::string &path, const std::string &prefix)
    : path(path)
    , prefix(prefix)
{
}

void ExternalManifestData::Save()
{
    if (external_manifests_data.find(path) != external_manifests_data.end())
        return;

    std::ifstream ifs(path);
    std::string data((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

    auto manifest = pbnjson::JDomParser::fromString(data, manifest_schema);
    const char *keys[] = { "roleFiles", "roleFilesPub", "roleFilesPrv", "serviceFiles",
                           "clientPermissionFiles", "apiPermissionFiles", "groupsFiles" };
    for (const auto &key : keys)
    {
        for (const auto &f :  manifest[key].items())
        {
            SaveFile(BuildFilename(prefix, f.asString()));
        }
    }

    external_manifests.emplace(path, prefix);
    external_manifests_data.emplace(path, std::move(data));
}

bool ExternalManifestData::LoadFromStorage(LSError *error)
{
    return ManifestData::ProcessManifest(path, prefix, *this, error);
}

void ExternalManifestData::LoadFromMemory()
{
    // Load cached manifest and associated files from RAM.
    auto manifest = pbnjson::JDomParser::fromString(external_manifests_data[path], manifest_schema);

    for (const auto &f :  manifest["roleFiles"].items())
    {
        auto fn = BuildFilename(prefix, f.asString());
        std::string data = external_manifests_data[fn];
        //TBD: Modify to read required permission and permissionLevel
        Permissions perms;
        RolePtr role(nullptr, LSHubRoleUnref);
        ServiceToTrustMap required_trust_level;
		std::string trustLevel;
        if (ParseRoleString(data, prefix, role, perms, required_trust_level, trustLevel, nullptr))
        {
            roles.push_back(std::move(role));
            std::move(perms.begin(), perms.end(), std::back_inserter(this->perms));
        }

        //TBD: Fill trust map for required trust
        // Make sure that require map is filled properly while parsing role file
         for (const auto &e : required_trust_level)
        {
            LOG_LS_DEBUG("NILESH >>>> %s : for [%s]", __func__, e.first);
            trust_level_required[e.first] = (e.second);
        }
    }

    for (const auto &f : manifest["roleFilesPub"].items())
    {
        auto fn = BuildFilename(prefix, f.asString());
        std::string data = external_manifests_data[fn];

        Permissions perms;
        RolePtr role(nullptr, LSHubRoleUnref);
        if (ParseOldRoleString(data, prefix, PUBLIC_BUS_ROLE, role, perms, nullptr))
        {
            // Don't add the role  for a triton  service, since triton will push
            // the role file when it wants to use it
            if (role->id.compare(g_conf_triton_service_exe_path) != 0)
            {
                roles.push_back(std::move(role));
            }
            std::move(perms.begin(), perms.end(), std::back_inserter(this->perms));
        }
    }

    for (const auto &f : manifest["roleFilesPrv"].items())
    {
        auto fn = BuildFilename(prefix, f.asString());
        std::string data = external_manifests_data[fn];

        Permissions perms;
        RolePtr role(nullptr, LSHubRoleUnref);
        if (ParseOldRoleString(data, prefix, PRIVATE_BUS_ROLE, role, perms, nullptr))
        {
            // Don't add the role  for a triton  service, since triton will push
            // the role file when it wants to use it
            if (role->id.compare(g_conf_triton_service_exe_path) != 0)
            {
                roles.push_back(std::move(role));
            }
            std::move(perms.begin(), perms.end(), std::back_inserter(this->perms));
        }
    }

    for (const auto &f : manifest["serviceFiles"].items())
    {
        auto fn = BuildFilename(prefix, f.asString());
        std::string data = external_manifests_data[fn];

        ServicePtr service(ParseServiceString(data, prefix, nullptr), _ServiceUnref);
        if (service)
        {
            services.push_back(std::move(service));
        }
    }

    for (const auto &f : manifest["clientPermissionFiles"].items())
    {
        auto fn = BuildFilename(prefix, f.asString());
        std::string data = external_manifests_data[fn];

        CategoryMap reqs;
        if (ParseRequiresString(data, reqs, nullptr))
        {
            for (const auto &child : reqs)
            {
                requires[child.first].insert(child.second);
            }
        }
    }

    for (const auto &f : manifest["apiPermissionFiles"].items())
    {
        auto fn = BuildFilename(prefix, f.asString());
        std::string data = external_manifests_data[fn];

        CategoryMap provs;
        if (ParseProvidesString(data, provs, nullptr))
        {
            for (const auto &child : provs)
            {
                provides[child.first].insert(child.second);
            }
        }
    }

    for (const auto &f : manifest["groupsFiles"].items())
    {
        auto fn = BuildFilename(prefix, f.asString());
        std::string data = external_manifests_data[fn];

        ServiceToTrustMap provided_trust_level;
        if (ParseGroupsString(data, provided_trust_level, nullptr))
        {
            for (const auto &e : provided_trust_level)
            {
                trust_level_provided[e.first] = (e.second);
            }
        }
    }
}

void ExternalManifestData::Remove()
{
    auto manifest = pbnjson::JDomParser::fromString(external_manifests_data[path], manifest_schema);

    for (const auto &f :  manifest["roleFiles"].items())
    {
        external_manifests_data.erase(BuildFilename(prefix, f.asString()));
    }

    for (const auto &f : manifest["roleFilesPub"].items())
    {
        external_manifests_data.erase(BuildFilename(prefix, f.asString()));
    }

    for (const auto &f : manifest["roleFilesPrv"].items())
    {
        external_manifests_data.erase(BuildFilename(prefix, f.asString()));
    }

    for (const auto &f : manifest["serviceFiles"].items())
    {
        external_manifests_data.erase(BuildFilename(prefix, f.asString()));
    }

    for (const auto &f : manifest["clientPermissionFiles"].items())
    {
        external_manifests_data.erase(BuildFilename(prefix, f.asString()));
    }

    for (const auto &f : manifest["apiPermissionFiles"].items())
    {
        external_manifests_data.erase(BuildFilename(prefix, f.asString()));
    }
	
	for (const auto &f : manifest["groupsFiles"].items())
    {
        external_manifests_data.erase(BuildFilename(prefix, f.asString()));
    }

    external_manifests.erase(path);
    external_manifests_data.erase(path);
}

void ExternalManifestData::SaveFile(const std::string &subfile)
{
    if (external_manifests_data.find(subfile) != external_manifests_data.end())
    {
        return;
    }

    std::ifstream ifs(subfile);
    std::string data((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    external_manifests_data.emplace(subfile, data);
}

void ManifestPriorityQueue::remove(const Manifest *ref)
{
    auto found = std::find(c.begin(), c.end(), ref);
    if (found != c.end())
    {
        c.erase(found);
        std::make_heap(c.begin(), c.end(), Base::comp);
    }
}

const Manifest* ManifestPriorityQueue::top() const
{
    if (c.empty())
        return nullptr;

    return Base::top();
}
