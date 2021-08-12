# Copyright (c) 2008-2021 LG Electronics, Inc.
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

# Default settings used for device. Target-specific overrides are done below.
# If you change a value here, check to see if the overrides below are still necessary.
set(CONF_GENERAL_PID_DIRECTORY "${WEBOS_INSTALL_RUNTIMEINFODIR}/ls2")
set(CONF_GENERAL_LOG_SERVICE_STATUS "false")
set(CONF_GENERAL_CONNECT_TIMEOUT "20000")

set(CONF_WATCHDOG_TIMEOUT "60")
set(CONF_FAILURE_MODE "noop")

set(CONF_DYNAMIC_SERVICES_EXEC_PREFIX "${WEBOS_INSTALL_SBINDIR}/setcpushares-ls2")
set(CONF_DYNAMIC_SERVICES_LAUNCH_TIMEOUT "300000")
set(CONF_SECURITY_ENABLED "true") # Enable security by default

set(CONF_SECURITY_MONITOR_EXE_PATH "${WEBOS_INSTALL_SBINDIR}/ls-monitor")
set(CONF_SECURITY_JS_SERVICE_EXE_PATH "js")
set(CONF_SECURITY_ALLOW_NULL_OUTBOUND_BY_DEFAULT "true")

set(CONF_SECURITY_CONTAINERS_DIRECTORY "${WEBOS_INSTALL_SYSBUS_CONTAINERSDIR}")
set(CONF_SECURITY_CONTAINERS_DIRECTORIES "${CONF_SECURITY_CONTAINERS_DIRECTORY}")
set(CONF_SECURITY_MANIFESTS_DIRECTORIES "${WEBOS_INSTALL_SYSBUS_MANIFESTSDIR}")
set(CONF_SECURITY_MANIFESTS_VOLATILE_DIRECTORIES "${WEBOS_INSTALL_SYSBUS_DYNMANIFESTSDIR};${WEBOS_INSTALL_SYSBUS_DEVMANIFESTSDIR}")
set(CONF_SECURITY_DEVMODE_CERTIFICATE "${WEBOS_INSTALL_SYSBUS_DEVDATADIR}/devmode_certificate.json")
set(CONF_SECURITY_DEFAULT_DEVMODE_CERTIFICATE "${WEBOS_INSTALL_SYSBUS_DATADIR}/devmode_certificate.json")
set(CONF_SECURITY_PROXY_AGENTS_DIRECTORY "${WEBOS_INSTALL_SYSBUS_PROXYAGENTSDIR}")
set(CONF_SECURITY_PROXY_AGENTS_DIRECTORIES "${CONF_SECURITY_PROXY_AGENTS_DIRECTORY}")

configure_file(ls-hubd.conf.in ls-hubd.conf @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/ls-hubd.conf
    DESTINATION ${WEBOS_INSTALL_SYSCONFDIR}/luna-service2
    COMPONENT config)
webos_build_configured_file(files/conf/pmlog/ls-hub.conf SYSCONFDIR pmlog.d)
