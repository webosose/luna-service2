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

#ifndef _MANIFEST_HPP_
#define _MANIFEST_HPP_

#include <mutex>
#include <queue>
#include <string>
#include <unordered_set>
#include <unordered_map>

#include <pbnjson.hpp>

#include "role.hpp"
#include "service.hpp"
#include "permission.hpp"
#include "semantic_version.hpp"
#include "groups.hpp"

struct Manifest
{
    Manifest(const std::string &path, const std::string &prefix = std::string());
    Manifest(const std::string &id, SemanticVersion &&version);

    bool parse(LSError *error);

    std::string id;
    std::string path;
    std::string prefix;
    SemanticVersion version;
};

struct ManifestPathHash
{
    size_t operator()(const Manifest &value) const noexcept
    {
        return std::hash<std::string>()(value.path);
    }
};

struct ManifestPathEqual
{
    bool operator()(const Manifest &lhs, const Manifest &rhs) const noexcept
    {
        return lhs.path == rhs.path;
    }
};

typedef std::unordered_set<Manifest, ManifestPathHash, ManifestPathEqual> Manifests;

struct ManifestLess
{
    bool operator()(const Manifest *lhs, const Manifest *rhs)
    {
        return lhs->version.compare(rhs->version) == SemanticVersion::Precedence::Lower;
    }
};

// manifests ordered by descending version
class ManifestPriorityQueue : public std::priority_queue
                                     <
                                        const Manifest*,
                                        std::vector<const Manifest*>,
                                        ManifestLess
                                     >
{
    typedef std::priority_queue
            <
                const Manifest*,
                std::vector<const Manifest*>,
                ManifestLess
            >
    Base;

public:
    void remove(const Manifest *ref);

    const Manifest* top() const;
};

class ManifestData
{

public:
    typedef std::vector<RolePtr> Roles;
    typedef std::vector<ServicePtr> Services;
    typedef std::vector<PermissionPtr> Permissions;

    ManifestData() = default;

    ManifestData(ManifestData&) = delete;
    ManifestData& operator=(const ManifestData&) = delete;

    ManifestData(ManifestData&&) = default;
    ManifestData& operator=(ManifestData&&) = default;

    static bool ProcessManifest(const std::string &path, const std::string &prefix, ManifestData& data, LSError *error);
    static bool ProcessManifest(const pbnjson::JValue &manifest, const std::string &prefix, ManifestData& data, LSError *error);

    Roles roles;
    Permissions perms;
    Services services;
    CategoryMap requires;
    CategoryMap provides;
    TrustMap access;

};

class ExternalManifestData : public ManifestData
{

public:
    ExternalManifestData(const std::string &path, const std::string &prefix);

    ExternalManifestData(ExternalManifestData&) = delete;
    ExternalManifestData& operator=(const ExternalManifestData&) = delete;

    ExternalManifestData(ExternalManifestData&&) = default;
    ExternalManifestData& operator=(ExternalManifestData&&) = default;

    // parse manifest and all its data and save it in string representation to global storage
    void Save();

    // load manifest and all its data from external storage
    // parse data that represented as string to corespondenting structures.
    bool LoadFromStorage(LSError *error);

    // load manifest and all its data from internal storage
    // parse data that represented as string to corespondenting structures.
    void LoadFromMemory();

    void Remove();

private:
    void SaveFile(const std::string &subfile);

    std::string path;
    std::string prefix;
};

// Map of fully qualified absolute path of manfiest to their prefix
extern std::unordered_map<std::string, std::string> external_manifests;

// Map of fully qualified absolute path of manfiest to their data, that was read from the path
extern std::unordered_map<std::string, std::string> external_manifests_data;

#endif //_MANIFEST_HPP_
