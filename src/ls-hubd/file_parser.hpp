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

#ifndef _FILE_PARSER_HPP_
#define _FILE_PARSER_HPP_

#include <string>
#include <memory>
#include <vector>

#include "role.hpp"
#include "manifest.hpp"
#include "permission.hpp"
#include "groups.hpp"

struct _Service;

class FileIterator
{
public:
    explicit FileIterator(const std::string& suffix = std::string());

    virtual void operator()(const std::string&) = 0;
    virtual const std::string& Suffix() const;
    virtual ~FileIterator() {}

private:
    std::string _suffix;
};

class FileCollector : public FileIterator
{
public:
    explicit FileCollector(const std::string& suffix = std::string());

    const std::vector<std::string>& Files() const;
    void operator()(const std::string& path);

private:
    std::vector<std::string> _files;
};
void DumpTrustMap(const TrustMap &trust_level, std::string &dump);
void DumpTrustMapToFile(std::string filename,ServiceToTrustMap &trust_level, std::string title);
std::string extract_filename(const std::string& filepath);

bool ProcessDirectory(const char *dir, void* ctx, LSError *lserror);

PermissionArray ParseJSONGetPermissions(const pbnjson::JValue &json, const std::string &id);
RolePtr ParseJSONGetRoleOld(const pbnjson::JValue &object, const std::string &prefix, uint32_t flags);
RolePtr ParseJSONGetRole(const pbnjson::JValue &json, const std::string &path, const std::string &prefix, LSError *error);
bool ParseJSONGetAPIVersions(const pbnjson::JValue &json, const std::string &path, PermissionArray &perms, LSError *error);

bool ParseRoleString(const std::string &data, const std::string &prefix, RolePtr &role,
               PermissionArray &perms, ServiceToTrustMap &trust_level, std::string &trustLevel, LSError *lserror);

bool ParseRoleFile(const std::string &path, const std::string &prefix, RolePtr &role,
                   PermissionArray &perms, ServiceToTrustMap &trust_level, std::string &trustLevel, LSError *lserror);

bool ParseOldRoleString(const std::string &data, const std::string &prefix, uint32_t flags, RolePtr &role,
                        PermissionArray &perms, LSError *lserror);
bool ParseOldRoleFile(const std::string &path, const std::string &prefix, uint32_t flags, RolePtr &role,
                      PermissionArray &perms, LSError *lserror);

_Service* ParseServiceString(const std::string &path, const std::string &prefix, LSError *error);
_Service* ParseServiceFile(const std::string &path, const std::string &prefix, LSError *error);

bool ParseRequiresString(const std::string &data, CategoryMap &requires, LSError *lserror);
bool ParseRequiresFile(const std::string &path, CategoryMap &requires, LSError *lserror);

bool ParseProvidesString(const std::string &data, CategoryMap &provides, LSError *lserror);
bool ParseProvidesFile(const std::string &path, CategoryMap &provides, LSError *lserror);

bool ParseGroupsString(const std::string &data, ServiceToTrustMap &trust_level, LSError *error);
bool ParseGroupsFile(const std::string &path, ServiceToTrustMap &trust_level, LSError *error);

bool 
ParseJSONGetRequiredTrust(const pbnjson::JValue &json, const std::string &path,
                       const std::string &prefix, ServiceToTrustMap &trust_level, LSError *error);
bool
ParseJSONGetRequiredPermissions(const pbnjson::JValue &json, const std::string &trust,
                                                         ServiceToTrustMap &trust_level, LSError *error);

void ParseServicetoTrustMap(pbnjson::JValue &object, ServiceToTrustMap &trust_level, LSError *error);

#endif //_FILE_PARSER_HPP_
