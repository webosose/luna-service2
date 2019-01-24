# Copyright (c) 2014-2019 LG Electronics, Inc.
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

set(UNIT_TEST_SOURCES
    test_error.cpp
    test_jsonpayload.cpp
    )

set(INTEGRATION_TEST_SOURCES
    test_client.cpp
    test_service.cpp
    test_category.cpp
    "test_call.cpp\;test_call_service.cpp"
    test_subscription_cxx.cpp
    test_subscription_cancel.cpp
    test_disconnection.cpp
    category_notification.cpp
    "test_example++.cpp"
    metainfo_example.cpp
    "test_idletimeout.cpp\;test_idletimeout_service.cpp"
    test_payload.cpp
    )

set(TEST_LIBRARIES
    ${PROJECT_NAME}
    ${WEBOS_GTEST_LIBRARIES}
    )

add_unit_test_cases("${UNIT_TEST_SOURCES}" "${TEST_LIBRARIES}")
add_integration_test_cases("integration.c++" "${INTEGRATION_TEST_SOURCES}" "${TEST_LIBRARIES}")
