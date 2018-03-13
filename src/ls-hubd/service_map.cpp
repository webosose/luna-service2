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

#include <string>
#include <sstream>

#include "log.h"
#include "error.h"
#include "service_map.hpp"

/** @cond INTERNAL */

ServiceMap::~ServiceMap()
{
    for (auto& service : _services)
        _ServiceUnref(service.second);
}

/**
 *******************************************************************************
 * @brief Add service to service map. Hash of service name to service ptr.
 *
 * @param  service  IN  service to add
 *******************************************************************************
 */
void ServiceMap::Add(ServicePtr service)
{
    for (int i = 0; i < service->num_services; ++i)
    {
        char const *service_name = service->service_names[i];

        LOG_LS_DEBUG("Adding service name: \"%s\" to service map\n", service_name);

        size_t prefix = strcspn(service_name, "*?");
        if (!service_name[prefix])
        {
            auto it = _services.find(service_name);
            if (it == _services.end())
            {
                _ServiceRef(service.get());
                _services.emplace(service_name, service.get());
            }
        }
        else
        {
            auto node = _wildcard_services.Add(service_name);
            if (!node->service)
            {
                _ServiceRef(service.get());
                node->service.reset(service.get());
            }
        }
    }
}

/**
 *******************************************************************************
 * @brief Remove service from service map by name.
 *
 * @param  service_names  IN  services to remove
 * @param  count          IN  @p service_names count
 *******************************************************************************
 */
void ServiceMap::Remove(const char** service_names, size_t count)
{
    for (size_t i = 0; i < count; ++i)
    {
        char const *service_name = service_names[i];

        LOG_LS_DEBUG("Removing service name: \"%s\" from service map\n", service_name);

        size_t prefix = strcspn(service_name, "*?");
        if (!service_name[prefix])
        {
            auto found = _services.find(service_name);
            if (found != _services.end())
            {
                _ServiceUnref(found->second);
                _services.erase(found);
            }
        }
        else
        {
            auto action = [](const char *, WildcardData &data)
            {
                data.service.reset();
            };

            _wildcard_services.Remove(service_name, action);
        }
    }
}

_Service* ServiceMap::Lookup(const std::string &service_name) const
{
    {
        /* First look up in the hash map for exact name */
        auto found = _services.find(service_name.c_str());
        if (found != _services.end())
            return found->second;
    }

    /* If not found, try to match against a pattern */
    _Service *last_service = nullptr;
    auto track_service = [&last_service](const WildcardData &data)
    {
        if (data.service)
            last_service = data.service.get();
    };

    _wildcard_services.Search(service_name.c_str(), track_service);

    return last_service;
}

/**
 *******************************************************************************
 * @brief Dump service map into a CSV text data
 *
 * @return  Text data
 *******************************************************************************
 */
std::string ServiceMap::DumpCsv() const
{
    std::ostringstream oss;

    auto dump_entry = [&oss](const std::string &name, const char *suffix, const _Service *svc)
    {
        // Keyword
        oss << "Service," << name.c_str() << suffix;
        // Dynamic flag
        oss << (svc->is_dynamic ? ",D" : ",S");
        // Executable path
        oss << "," << svc->exec_path;
        oss << '\n';
    };

    for (const auto &entry : _services)
        dump_entry(entry.first, "", entry.second);

    auto action = [&](const std::string &key, const WildcardData &data)
    {
        if (data.service)
            dump_entry(key, "*", data.service.get());
    };

    _wildcard_services.Visit(action);

    return oss.str();
}

/** @endcond INTERNAL */
