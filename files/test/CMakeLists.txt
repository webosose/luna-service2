# Copyright (c) 2015-2018 LG Electronics, Inc.
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

# This is reflected from webos_test_provider bbclass, so it shouldn't be changed
set(TEST_INSTALL_DIR "${WEBOS_INSTALL_TESTSDIR}/${CMAKE_PROJECT_NAME}" CACHE INTERNAL "Path to tests bundle")
set(PERF_INSTALL_DIR "${WEBOS_INSTALL_TESTSDIR}/${CMAKE_PROJECT_NAME}-perf" CACHE INTERNAL "Path to perf bundle")

# Usage: add_unit_test_case(source libraries)
#
# <source> source that produce one test case
# <libraries> list of libraries to link
#
# Test name will be set from source name
macro(add_unit_test_case source libraries)
    get_filename_component(name ${source} NAME_WE)
    add_executable(${name} ${source})
    set_target_properties(${name} PROPERTIES COMPILE_FLAGS "-DLS_SCHEMA_ROOT=\\\"${CMAKE_SOURCE_DIR}/files/schema\\\"")

    target_link_libraries(${name} ${libraries})
    if (WEBOS_CONFIG_INSTALL_TESTS)
        install(TARGETS ${name} DESTINATION "${TEST_INSTALL_DIR}/unit")
    endif()
    add_test(${name} ${name})
    unset(name)
endmacro()

# Usage: add_unit_test_cases(sources libraries)
#
# <sources> list of sorces
# <libraries> list of libraries to link
#
# Test name will be set from source name
macro(add_unit_test_cases sources libraries)
    foreach(source ${sources})
        add_unit_test_case(${source} "${libraries}")
    endforeach()
endmacro()

# Usage: build_integration_test_case(test_case libraries)
#
# Builds each test in test case and links it with libraries
#
# <test_case> list of test case's sources
# <libraries> list of libraries to link
macro(build_integration_test_case test_case libraries)
    foreach(source ${test_case})
        get_filename_component(target ${source} NAME_WE)
        add_executable(${target} ${source})
        target_link_libraries(${target} ${libraries})
        unset(target)
    endforeach()
endmacro()

# Usage: add_integration_test_case(prefix test_case libraries)
#
# <prefix>    prefix for each tests' name
# <test_case> list of test case's sources
# <libraries> list of libraries to link
#
# Test's name and config will be set from first source in test case
macro(add_integration_test_case prefix test_case libraries)
    build_integration_test_case("${test_case}" "${libraries}")

    set(test_case_v ${test_case})
    list(GET test_case_v 0 source0)
    get_filename_component(test_name ${source0} NAME_WE)
    if(WEBOS_CONFIG_INSTALL_TESTS)
        set(install_dir "${TEST_INSTALL_DIR}/integration")
        install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/${test_name}.conf DESTINATION ${install_dir})
        foreach(source ${test_case})
            get_filename_component(target ${source} NAME_WE)
            install(TARGETS ${target} DESTINATION ${install_dir})
        endforeach()
        unset(install_dir)
    endif()
    add_test(NAME ${prefix}.${test_name} COMMAND ${CMAKE_BINARY_DIR}/run_with_hub
             ${CMAKE_CURRENT_SOURCE_DIR}/${test_name}.conf)
    unset(test_name)
    unset(test_case_v)
endmacro()

# Usage: add_performance_test_case(prefix test_case libraries [NOHUB])
#
# <prefix>    prefix for each tests' name
# <test_case> list of test case's sources
# <libraries> list of libraries to link
#
# Test's name and config will be set from first source in test case
# If NOHUB is given, the test is self-contained and doesn't require hub running,
# thus, no config file is needed.
macro(add_performance_test_case prefix test_case libraries)
    cmake_parse_arguments(test "NOHUB" "" "" ${ARGN})

    build_integration_test_case("${test_case}" "${libraries}")

    if(WEBOS_CONFIG_INSTALL_TESTS)
        set(test_case_v ${test_case})
        list(GET test_case_v 0 source0)
        get_filename_component(test_name ${source0} NAME_WE)

        if(NOT test_NOHUB)
            install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/${test_name}.conf DESTINATION ${PERF_INSTALL_DIR})
        endif()

        foreach(source ${test_case})
            get_filename_component(target ${source} NAME_WE)
            install(TARGETS ${target} DESTINATION ${PERF_INSTALL_DIR})
        endforeach()

        unset(test_name)
        unset(test_case_v)
    endif()
endmacro()

# Usage: add_integration_test_cases(prefix test_cases libraries)
#
# <prefix> prefix for each tests' name
# <test_cases> list of test cases' sources
# <libraries> libraries to link
#
# Test's name and config will be set from first source in test case
macro(add_integration_test_cases prefix test_cases libraries)
    foreach(test_case ${test_cases})
        add_integration_test_case(${prefix} "${test_case}" "${libraries}")
    endforeach()
endmacro()

configure_file(libtest.sh.in libtest.sh @ONLY)
configure_file(run_test.in run_test @ONLY)
configure_file(run_all_tests.in run_all_tests @ONLY)
configure_file(run_with_hub.in ${CMAKE_BINARY_DIR}/run_with_hub @ONLY)
configure_file(coverage.in ${CMAKE_BINARY_DIR}/coverage @ONLY)

if(WEBOS_CONFIG_INSTALL_TESTS)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libtest.sh DESTINATION ${TEST_INSTALL_DIR})
    install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/run_test DESTINATION ${TEST_INSTALL_DIR})
    install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/run_all_tests DESTINATION ${TEST_INSTALL_DIR})

    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libtest.sh DESTINATION "${PERF_INSTALL_DIR}")
    install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/run_test DESTINATION "${PERF_INSTALL_DIR}")
endif()
