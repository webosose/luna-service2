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

project(ls-hubd)

set(PROJECT_SOURCES
    hublane.cpp
    conf.cpp
    pattern.cpp
    patternqueue.cpp
    hub.cpp
    role.cpp
    service.cpp
    role_map.cpp
    active_role_map.cpp
    permission.cpp
    service_permissions.cpp
    permissions_map.cpp
    active_permission_map.cpp
    groups_map.cpp
    security.cpp
    semantic_version.cpp
    watchdog.cpp
    client_id.cpp
    client_map.cpp
    signal_map.cpp
    file_parser.cpp
    file_schema.cpp
    manifest.cpp
    hub_service.cpp
    service_map.cpp
    )

webos_add_compiler_flags(ALL --std=c++11)

# The following definitions avoid the need to configure any source files
add_definitions(-DDEFAULT_MONITOR_EXE_PATH="${WEBOS_INSTALL_SBINDIR}/ls-monitor")

if(SECURITY_HACKS_ENABLED)
add_definitions(-DSECURITY_HACKS_ENABLED)
endif()

if (LS_VALIDATE_CONF)
    add_definitions(-DLS_VALIDATE_CONF)
endif()

set(LIBRARIES
    luna-service2
    luna-service2++
    ${PMLOGLIB_LIBRARIES}
    ${PBNJSON_CXX_LIBRARIES}
    )

add_executable(${PROJECT_NAME} ${PROJECT_SOURCES})
target_link_libraries(${PROJECT_NAME} ${LIBRARIES})

if (WEBOS_CONFIG_BUILD_TESTS)
    # Build modified hubd for tests
    add_library(ls-hublib-test SHARED ${PROJECT_SOURCES})
    set_target_properties(ls-hublib-test
        PROPERTIES COMPILE_FLAGS "-DUNIT_TESTS -DLS_SCHEMA_ROOT=\\\"${CMAKE_SOURCE_DIR}/files/schema\\\"")
    target_link_libraries(ls-hublib-test ${LIBRARIES})

    if (WEBOS_CONFIG_INSTALL_TESTS)
        install(TARGETS ls-hublib-test DESTINATION "${TEST_INSTALL_DIR}/lib")
    endif()

    add_executable(ls-hubd-test ${PROJECT_SOURCES})
    set_target_properties(ls-hubd-test PROPERTIES COMPILE_FLAGS "-DINTEGRATION_TESTS")
    target_link_libraries(ls-hubd-test ${LIBRARIES})

    add_subdirectory(test)
    add_subdirectory(performance)
else()
    message(STATUS "ls-hubd: skipping automatic tests")
endif()

webos_build_daemon(NAME ${PROJECT_NAME} LAUNCH ${CMAKE_SOURCE_DIR}/files/launch/ ${LS2_RESTRICTED})
