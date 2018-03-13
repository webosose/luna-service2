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

/**
 *  @file test_security_util.hpp
 */

#pragma once

#include <string>

/// @cond INTERNAL
const std::string &testDataPath()
{
    static std::string path = []() {
        const char *value = getenv("LS2_TEST_DATA_PATH");
        return value ? value : TEST_DATA_PATH;
    }();
    return path;
}

const std::string steady_roles_old = testDataPath() + "/oldformat/steady/roles";
const std::string steady_roles = testDataPath() + "/steady/roles";
const std::string steady_services = testDataPath() + "/steady/services";
const std::string volatile_roles_old = testDataPath() + "/oldformat/volatile/roles";
const std::string volatile_roles = testDataPath() + "/volatile/roles";
const std::string volatile_services = testDataPath() + "/volatile/services";
const std::string containers_dir = testDataPath() + "/containers.d";
const std::string permissions_dir = testDataPath() + "/permissions.d";
const std::string volatile_dir = testDataPath() + "/volatile";
const std::string manifests_dir = testDataPath() + "/manifests";

const std::string malformed_roles = testDataPath() + "/malformed/steady/roles";
const std::string malformed_permissions = testDataPath() + "/malformed/permissions.d";
/// @endcond
