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

#include "file_schema.hpp"
#include "log.h"

namespace {
    pbnjson::JSchema getSchema(const char *id)
    {
#ifdef LS_VALIDATE_CONF
#ifndef LS_SCHEMA_ROOT
        std::string schema_root(WEBOS_INSTALL_WEBOS_SYSCONFDIR"/schemas/luna-service2");
#else
        std::string schema_root(LS_SCHEMA_ROOT);
#endif
        auto path = schema_root + "/" + id + ".schema";
        auto schema = pbnjson::JSchema::fromFile(path.c_str());
        if (!schema)
        {
            LOG_LS_DEBUG("Failed to load schema %s from file %s. No validation will be done", id, path.c_str());
            return pbnjson::JSchema::AllSchema();
        }
        else
        {
            return schema;
        }
#else
        // no validation for conf files
        return pbnjson::JSchema::AllSchema();
#endif
    }
} // anonymous namespace

pbnjson::JSchema old_role_schema = getSchema("old_role");
pbnjson::JSchema role_schema = getSchema("role");
pbnjson::JSchema api_permissions_schema = getSchema("api_permissions");
pbnjson::JSchema client_permissions_schema = getSchema("client_permissions");
pbnjson::JSchema manifest_schema = getSchema("manifest");
pbnjson::JSchema container_schema = getSchema("container");
pbnjson::JSchema groups_schema = getSchema("groups");