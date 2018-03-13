# Copyright (c) 2014-2018 LG Electronics, Inc.
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

project(luna-service2++)

set(SOURCES
    call.cpp
    condition_variable.cpp
    handle.cpp
    json_payload.cpp
    message.cpp
    palm_service.cpp
    subscription.cpp
    transport.cpp
    )

set(HEADERS
    ${PRIVATE_INCLUDES}/json_payload.hpp
    ${PRIVATE_INCLUDES}/transport.hpp
    ${PRIVATE_INCLUDES}/util.hpp
    ${PUBLIC_INCLUDES}/luna-service2/lunaservice.hpp
    ${PUBLIC_INCLUDES}/${PROJECT_NAME}/call.hpp
    ${PUBLIC_INCLUDES}/${PROJECT_NAME}/error.hpp
    ${PUBLIC_INCLUDES}/${PROJECT_NAME}/handle.hpp
    ${PUBLIC_INCLUDES}/${PROJECT_NAME}/message.hpp
    ${PUBLIC_INCLUDES}/${PROJECT_NAME}/palm_service.hpp
    ${PUBLIC_INCLUDES}/${PROJECT_NAME}/payload.hpp
    ${PUBLIC_INCLUDES}/${PROJECT_NAME}/server_status.hpp
    ${PUBLIC_INCLUDES}/${PROJECT_NAME}/subscription.hpp
    )

include_directories(${PUBLIC_INCLUDES}/luna-service2++)

webos_add_compiler_flags(ALL -Wall -std=c++11)

add_library(${PROJECT_NAME} SHARED ${SOURCES} ${HEADERS})
target_link_libraries(${PROJECT_NAME} luna-service2 ${PBNJSON_CXX_LIBRARIES})
webos_add_linker_options(ALL ${PBNJSON_CXX_LDFLAGS})

if (WEBOS_CONFIG_BUILD_TESTS)
    add_subdirectory(test)
else()
    message(STATUS "libluna-service2++: skipping automatic tests")
endif()

webos_build_library(NAME ${PROJECT_NAME})
