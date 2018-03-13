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

project(luna-service2)

set(SOURCES
    base.c
    callmap.c
    category.c
    clock.c
    simple_pbnjson.c
    debug_methods.c
    mainloop.c
    message.c
    payload.c
    subscription.c
    timersource.c
    transport.c
    transport_channel.c
    transport_client.c
    transport_incoming.c
    transport_message.c
    transport_outgoing.c
    transport_security.c
    transport_serial.c
    transport_shm.c
    transport_signal.c
    transport_utils.c
    utils.c
    uri.c
    )

set(HEADERS
    base.h
    category.h
    clock.h
    debug_methods.h
    error.h
    log.h
    log_ids.h
    message.h
    payload_internal.h
    subscription.h
    timersource.h
    transport_channel.h
    transport_client.h
    transport.h
    transport_handlers.h
    transport_incoming.h
    transport_message.h
    transport_outgoing.h
    transport_priv.h
    transport_security.h
    transport_serial.h
    transport_shm.h
    transport_signal.h
    transport_utils.h
    uri.h
    utils.h
    ${PRIVATE_INCLUDES}/simple_pbnjson.h
    ${PUBLIC_INCLUDES}/${PROJECT_NAME}/payload.h
    ${PUBLIC_INCLUDES}/${PROJECT_NAME}/lunaservice.h
    ${PUBLIC_INCLUDES}/${PROJECT_NAME}/lunaservice-errors.h
    ${PUBLIC_INCLUDES}/${PROJECT_NAME}/lunaservice-meta.h
    )

webos_add_compiler_flags(ALL -Wall -std=c99)

add_definitions(-D_GNU_SOURCE)
add_definitions(-DDEFAULT_HUB_LOCAL_SOCKET_DIRECTORY="${WEBOS_INSTALL_RUNTIMEINFODIR}/luna-service2")

if (LS_VALIDATE_REPLIES)
    add_definitions(-DLS_VALIDATE_REPLIES)
endif()

set(LIBRARIES
    ${GLIB2_LIBRARIES}
    ${GTHREAD2_LIBRARIES}
    ${PBNJSON_C_LIBRARIES}
    ${PMLOGLIB_LIBRARIES}
    dl
    pthread
    rt
    )

set(LIBRARIES_LDFLAGS
    ${GLIB2_LDFLAGS_OTHER}
    ${GTHREAD2_LDFLAGS_OTHER}
    ${PBNJSON_C_LDFLAGS_OTHER}
    ${PMLOGLIB_LDFLAGS_OTHER}
    )

if (SECURITY_HACKS_ENABLED)
    list(APPEND SOURCES security_hacks.c)
    list(APPEND HEADERS ${PRIVATE_INCLUDES}/security_hacks.h)
    add_definitions(-DSECURITY_HACKS_ENABLED)
endif()

# Enable LLtng
if(WEBOS_LTTNG_ENABLED)
    list(APPEND SOURCES pmtrace_ls2_provider.c)
    list(APPEND HEADERS pmtrace_ls2.h pmtrace_ls2_provider.h)
    list(APPEND LIBRARIES urcu-bp lttng-ust)
    add_definitions(-DHAS_LTTNG)
endif()

add_library(${PROJECT_NAME} SHARED ${SOURCES} ${HEADERS})
target_link_libraries(${PROJECT_NAME} ${LIBRARIES})
webos_add_linker_options(ALL ${LIBRARIES_LDFLAGS})

if (WEBOS_CONFIG_BUILD_TESTS)
    add_subdirectory(test)
else()
    message(STATUS "libluna-service2: skipping automatic tests")
endif()

webos_build_library(NAME ${PROJECT_NAME})
