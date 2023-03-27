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

project(ls-monitor)

set(PROJECT_SOURCES
    monitor.cpp
    monitor_queue.cpp
    json_output.cpp
    )

webos_add_compiler_flags(ALL --std=c++14)

if(WEBOS_TARGET_MACHINE_IMPL STREQUAL guest)
	add_definitions(-DPID_DIR="/tmp")
else()
	add_definitions(-DPID_DIR="${WEBOS_INSTALL_RUNTIMEINFODIR}/ls2")
endif()

add_executable(${PROJECT_NAME} ${PROJECT_SOURCES})
target_link_libraries(${PROJECT_NAME} ${PBNJSON_CXX_LIBRARIES} luna-service2++)

if (WEBOS_CONFIG_BUILD_TESTS)
    add_subdirectory(test)
else()
    message(STATUS "ls-monitor: skipping automatic tests")
endif()

webos_build_program(NAME ${PROJECT_NAME} ADMIN ${LS2_RESTRICTED})
