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

#ifndef _SERVICE_MAP_HPP_
#define _SERVICE_MAP_HPP_

#include <map>
#include <unordered_map>

#include "service.hpp"
#include "trie.hpp"

class ServiceMap
{

public:
    ServiceMap() = default;
    ~ServiceMap();

    ServiceMap(const ServiceMap&) = delete;
    ServiceMap& operator=(const ServiceMap&) = delete;

    ServiceMap(ServiceMap&&) = default;
    ServiceMap& operator=(ServiceMap&&) = default;

    void Add(ServicePtr service);
    void Remove(const char **service_names, size_t count);

    _Service* Lookup(const std::string &service_name) const;

    std::string DumpCsv() const;

private:
    std::unordered_map<std::string, _Service*> _services;

    struct WildcardData
    {
        ServicePtr service;

        bool IsEmpty() const { return !service; }

        WildcardData() : service(nullptr, _ServiceUnref) {}
    };

    Trie<WildcardData> _wildcard_services;
};

#endif //_SERVICE_MAP_HPP_
