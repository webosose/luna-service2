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

#ifndef _HUB_SERVICE_HPP_
#define _HUB_SERVICE_HPP_

#include <string>
#include <set>
#include <memory>
#include <unordered_map>

typedef struct LSTransportMessage _LSTransportMessage;

class HubService
{
    typedef std::string (HubService::*method_t)(_LSTransportMessage *, const char *);

public:
    static HubService& instance();

    HubService(const HubService &) = delete;
    HubService &operator=(const HubService &) = delete;

    HubService(HubService &&) = delete;
    HubService &operator=(HubService &&) = delete;

    void HandleMethodCall(_LSTransportMessage *message);

private:
    HubService();

    std::string IsCallAllowed(_LSTransportMessage *message, const char *payload);
    std::string AddOneManifest(_LSTransportMessage *message, const char *payload);
    std::string RemoveOneManifest(_LSTransportMessage *message, const char *payload);
    std::string AddManifestsDir(_LSTransportMessage *message, const char *payload);
    std::string RemoveManifestsDir(_LSTransportMessage *message, const char *payload);
    std::string GetServiceApiVersions(_LSTransportMessage *message, const char *payload);
    std::string QueryServicePermissions(_LSTransportMessage *message, const char *payload);

private:
    std::unordered_map<std::string, method_t> _methods_map;
};

#endif //_HUB_SERVICE_HPP_
