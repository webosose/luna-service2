# Copyright (c) 2016-2018 LG Electronics, Inc.
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

add_performance_test_case("performance.performance" "performance.cpp" "${LIBRARIES}")
add_performance_test_case("performance.hub_performance" "bench_security_data.cpp" "${LIBRARIES};ls-hublib-test" NOHUB)
add_performance_test_case("performance.hub_memory" "hub_memory.cpp" "${LIBRARIES}")
add_performance_test_case("performance.lib_memory" "lib_memory.cpp" "${LIBRARIES}")
