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

set(UNIT_TEST_SOURCES
    test_base.c
    test_callmap.c
    test_clock.c
    test_debug_methods.c
    test_mainloop.c
    test_message.c
    test_subscription.c
    test_timersource.c
    test_transport_channel.c
    test_transport_client.c
    test_transport_incoming.c
    test_transport_message.c
    test_transport_outgoing.c
    test_transport_security.c
    test_transport_serial.c
    test_transport_shm.c
    test_transport_signal.c
    test_transport_utils.c
    test_transport.c
    test_utils.c
    )

set(INTEGRATION_TEST_SOURCES
    "test_example.c"
    )

set(TEST_LIBRARIES
    ${PROJECT_NAME}
    )

add_unit_test_cases("${UNIT_TEST_SOURCES}" "${TEST_LIBRARIES}")
add_integration_test_cases("integration.c" "${INTEGRATION_TEST_SOURCES}" "${TEST_LIBRARIES}")
