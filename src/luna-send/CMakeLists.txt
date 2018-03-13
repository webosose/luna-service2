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

project(luna-send)

webos_add_compiler_flags(ALL --std=c++11)

add_executable(${PROJECT_NAME} luna-send.cpp)
target_link_libraries(${PROJECT_NAME} ${CMAKE_PROJECT_NAME})

add_executable(${PROJECT_NAME}-pub luna-send.cpp)
target_link_libraries(${PROJECT_NAME}-pub ${CMAKE_PROJECT_NAME})
set_target_properties(${PROJECT_NAME}-pub PROPERTIES COMPILE_DEFINITIONS "PUBLIC_HUB_ONLY")

if (WEBOS_CONFIG_BUILD_TESTS)
    add_subdirectory(test)
else()
    message(STATUS "luna-send: skipping automatic tests")
endif()

webos_build_program(NAME ${PROJECT_NAME} ${LS2_RESTRICTED})
webos_build_program(NAME ${PROJECT_NAME}-pub)
