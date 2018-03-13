# Copyright (c) 2008-2018 LG Electronics, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

# Tests initially configured to lookup data folder within installed folders
set(TEST_DATA_PATH "${TEST_INSTALL_DIR}/data")
add_definitions(-DTEST_DATA_PATH="${TEST_DATA_PATH}")

if(WEBOS_CONFIG_INSTALL_TESTS)
    install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/data" DESTINATION "${TEST_INSTALL_DIR}")
endif()

add_definitions(-DUNIT_TESTS)

set(UNIT_TEST_SOURCES
    test_trie.cpp
    test_maps.cpp
    test_groups.cpp
    test_pattern.cpp
    test_security.cpp
    test_security_data.cpp
    test_directories_scan.cpp
    test_api_version_parser.cpp
    test_manifest.cpp
    test_semantic_version.cpp
    )

set(INTEGRATION_TEST_SOURCES
    "nosecurity_allowed_names.cpp"
    "security_allowed_names.cpp"
    "nosecurity_permissions.cpp"
    "security_permissions.cpp"
    "nosecurity_push_role.cpp"
    "security_push_role.cpp"
    "nosecurity_groups.cpp"
    "security_groups.cpp"
    "security_new2old_client.cpp\;security_new2old_service.cpp"
    "security_old2new_client.cpp\;security_old2new_service.cpp"
    "security_app_container.cpp"
    "security_allowed_call.cpp"
    "security_signals.cpp"
    "service_migration.cpp"
    "test_api_versions.cpp"
    "migrated_service_names"
    "external_manifest"
    "unregister.cpp\;unregister_foo"
    "lscallcancel.cpp"
    "security_restricted"
    "security_query_permissions"
    "server_status"
    "introspection\;introspection_service"
    "missing_file"
    )

if(SECURITY_HACKS_ENABLED)
    list(APPEND INTEGRATION_TEST_SOURCES "security_trusted.cpp\;security_trusted_any.cpp")
endif()

set(TEST_LIBRARIES
    ${LIBRARIES}
    ${WEBOS_GTEST_LIBRARIES}
    )

add_unit_test_cases("${UNIT_TEST_SOURCES}" "ls-hublib-test;${TEST_LIBRARIES}")
add_integration_test_cases("integration.hub" "${INTEGRATION_TEST_SOURCES}" "${TEST_LIBRARIES}")

# Run tests that use TEST_DATA_PATH with overriden path via env var
# LS2_TEST_DATA_PATH.
set_property(
    TEST
        test_security
        test_directories_scan
        test_manifest
        integration.hub.external_manifest
    PROPERTY
        ENVIRONMENT
            "LS2_TEST_DATA_PATH=${CMAKE_CURRENT_SOURCE_DIR}/data"
    )
