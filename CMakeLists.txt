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

cmake_minimum_required(VERSION 2.8.7)
project(luna-service2)

include(webOS/webOS)

webos_modules_init(1 6 1)
webos_component(3 21 2)

include(FindPkgConfig)

include_directories(src/libluna-service2)
include_directories(include/public)
include_directories(include/private)

set(PRIVATE_INCLUDES ${CMAKE_SOURCE_DIR}/include/private)
set(PUBLIC_INCLUDES ${CMAKE_SOURCE_DIR}/include/public)

pkg_check_modules(GLIB2 REQUIRED glib-2.0>=2.32.1)
include_directories(${GLIB2_INCLUDE_DIRS})
link_directories(${GLIB2_LIBRARY_DIRS})
webos_add_compiler_flags(ALL ${GLIB2_CFLAGS_OTHER})

# check for pbnjson c library
pkg_check_modules(PBNJSON_C REQUIRED pbnjson_c>=2.13.0)
include_directories(${PBNJSON_C_INCLUDE_DIRS})
link_directories(${PBNJSON_C_LIBRARY_DIRS})
webos_add_compiler_flags(ALL ${PBNJSON_C_CFLAGS_OTHER})

# check for pbnjson c++ library
pkg_check_modules(PBNJSON_CXX REQUIRED pbnjson_cpp>=2.13.0)
include_directories(${PBNJSON_CXX_INCLUDE_DIRS})
link_directories(${PBNJSON_CXX_LIBRARY_DIRS})
webos_add_compiler_flags(ALL ${PBNJSON_CXX_CFLAGS_OTHER})

# check if we have PmLogLib
pkg_check_modules(PMLOGLIB REQUIRED PmLogLib>=3.0.2)
include_directories(${PMLOGLIB_INCLUDE_DIRS})
link_directories(${PMLOGLIB_LIBRARY_DIRS})
webos_add_compiler_flags(ALL ${PMLOGLIB_CFLAGS_OTHER})

webos_machine_impl_dep()
include(webOS/LegacyDefines)

webos_include_install_paths()

set(LS2_PERMS "")
set(LS2_RESTRICTED "")

if(WEBOS_TARGET_MACHINE_IMPL STREQUAL hardware)
	# Only root (owner) will be permitted access to certain binaries on device
	set(LS2_PERMS PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE)

	# XXX Convert this to VERY_RESTRICTED_PERMISSIONS
	# once it is implemented.
	set(LS2_RESTRICTED RESTRICTED_PERMISSIONS)
endif()

if("${WEBOS_DISTRO_PRERELEASE}" STREQUAL "")
	webos_add_compiler_flags(ALL -DWEBOS_MASS_PRODUCTION)
	set(WEBOS_IS_PRERELEASE OFF)
else()
	# Enable asserts in development release builds
	webos_add_compiler_flags(ALL -UNDEBUG)
	set(WEBOS_IS_PRERELEASE ON)
endif()

# Next few flags will be enabled by default for pre-release build
set(SECURITY_HACKS_ENABLED ${WEBOS_IS_PRERELEASE} CACHE BOOL "Turn OFF to disable security hacks")
set(LS_VALIDATE_REPLIES ${WEBOS_IS_PRERELEASE} CACHE BOOL "Turn OFF to disable replies validation")
set(LS_VALIDATE_CONF ${WEBOS_IS_PRERELEASE} CACHE BOOL "Turn OFF to disable configuration files validation")

set(WEBOS_USE_WERROR FALSE CACHE BOOL "Set to TRUE to enable -Werror")
if(WEBOS_USE_WERROR)
	message("Build with treating most warnings as errors")
	webos_add_compiler_flags(ALL
	                        -Werror -Wextra
	                        -Wno-error=missing-field-initializers
	                        -Wno-error=unused-parameter
	                        -Wno-error=sign-compare
	                        -Wno-error=type-limits
	                        )
endif()

set(WEBOS_GCOVR_REPORT LS2_INVALID_PATH CACHE FILEPATH
	"Path to the previous gcovr coverage result. Set to any value if you need coverage target")

if(WEBOS_USE_GCOV OR (NOT WEBOS_GCOVR_REPORT STREQUAL LS2_INVALID_PATH))
	message(STATUS "Building with gcov support")

	# Build unit-tests, to test coverage
	set(WEBOS_CONFIG_BUILD_TESTS TRUE CACHE BOOL "Unit-tests were enabled to test coverage" FORCE)

	webos_add_compiler_flags(ALL --coverage)
	webos_add_linker_options(ALL -lgcov)

	if(WEBOS_GCOVR_REPORT)
		add_custom_target(coverage ${CMAKE_BINARY_DIR}/coverage
		                  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

		find_program(GCOV_PATH gcov)
		if(NOT GCOV_PATH)
			message(FATAL_ERROR "gcov not found. Install gcov, to use 'coverage' target")
		endif()

		find_program(GCOVR_PATH gcovr)
		if(NOT GCOVR_PATH)
			message(FATAL_ERROR "gcovr not found. Install gcovr, to use 'coverage' target")
		endif()
	endif()
endif()

set(WEBOS_CONFIG_BUILD_TESTS FALSE CACHE BOOL "Set to TRUE to enable tests compilation")
if (WEBOS_CONFIG_BUILD_TESTS)
	set(MEMORYCHECK_COMMAND_OPTIONS "--tool=memcheck --leak-check=full --trace-children=yes")
	set(MEMORYCHECK_SUPPRESSIONS_FILE "${CMAKE_SOURCE_DIR}/valgrind.supp")
	include(CTest)

	webos_use_gtest()
	add_subdirectory(files/test)
	include_directories(include/private/tests)
	include_directories(${WEBOS_GTEST_INCLUDES})

	add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure -E 'integration|test_clock|test_timersource')
	add_custom_target(check-security COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure -R 'security')
endif()

# Use PmLogLib
webos_add_compiler_flags(ALL -DUSE_PMLOG_DECLARATION)

# Debug definitions
webos_add_compiler_flags(ALL -DMEMCHECK -DLSHANDLE_CHECK)

# Turn on all warnings
webos_add_compiler_flags(ALL -Wall -Werror=switch)

# Enable security compatibility layer for public/private emulation.
webos_add_compiler_flags(ALL -DSECURITY_COMPATIBILITY)

# Specify which symbols are to be exported
# TODO: Create this
#webos_add_linker_options(ALL --version-script=${PROJECT_SOURCE_DIR}/src/libluna-service2/luna-service2Exports.map )

# Require that all undefined symbols are satisfied by the libraries from target_link_libraries()
webos_add_linker_options(ALL --no-undefined)

# XXX_ The libraries that come with gcc fail when --no-allow-shlib-undefined is specified
#webos_add_linker_options(ALL --no-allow-shlib-undefined)

add_subdirectory(src/libluna-service2)
add_subdirectory(src/libluna-service2++)
add_subdirectory(src/ls-hubd)
add_subdirectory(src/ls-monitor)
add_subdirectory(src/luna-send)
add_subdirectory(files/conf)

webos_build_pkgconfig(files/pkgconfig/${CMAKE_PROJECT_NAME})
webos_build_pkgconfig(files/pkgconfig/${CMAKE_PROJECT_NAME}++)

if(WEBOS_CONFIG_BUILD_DOCS)
	add_subdirectory(doc)
else()
	message(STATUS "Skipping document generation")
endif()

webos_build_system_bus_files()

install(DIRECTORY files/schema/
	DESTINATION ${WEBOS_INSTALL_WEBOS_SYSCONFDIR}/schemas/luna-service2
	PATTERN "*.schema"
	)

# install the script file
webos_configure_source_files(LS-CONTROL files/scripts/public/ls-control)
install(PROGRAMS ${LS-CONTROL} DESTINATION ${WEBOS_INSTALL_SBINDIR} ${LS2_PERMS})

# Create the permanent service directories. The ones for downloaded services (called
# "dynamic" but not to be confused with services that are started on-demand, which
# are known as "dynamic services") are created at boot time by the ls-hubd-private
# launch script.
#
# The permanent roles directories are created as part of the installation of roles
# files for ls-monitor and luna-send.
install(DIRECTORY DESTINATION ${WEBOS_INSTALL_SYSBUS_PRVSERVICESDIR})
install(DIRECTORY DESTINATION ${WEBOS_INSTALL_SYSBUS_PUBSERVICESDIR})
